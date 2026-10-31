//! §16.1 事务：原子性；并发写冲突的检测（基于属性的测试，≥ 10⁴ 个随机用例）。

use std::collections::{BTreeMap, BTreeSet};

use aos_branch::{BranchId, Cmp, Predicate, StoreError, TxMeta};
use aos_conformance::{assert_replay_matches, item, n_of, new_store, set, values};
use aos_types::{Actor, Name, ObjectRef, Origin, Taint, Timestamp, Ulid, Value};
use proptest::prelude::*;

const MAIN: BranchId = BranchId::Main;

#[test]
fn a_transaction_applies_all_or_nothing() {
    let mut s = new_store();
    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(&mut s, MAIN, a, 1);
    set(&mut s, MAIN, b, 1);
    let log_len = s.log().len();

    let mut tx = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
    s.put(&mut tx, item(a, 10)).unwrap();
    s.put(&mut tx, item(b, 10)).unwrap();
    set(&mut s, MAIN, b, 2); // a concurrent transaction changes b
    assert_eq!(s.apply(tx), Err(StoreError::Conflict(vec![b])));
    assert_eq!(values(&s, MAIN), BTreeMap::from([(a, 1), (b, 2)]), "a must not change either");
    assert_eq!(s.log().len(), log_len + 1, "only the concurrent transaction was logged");
}

#[test]
fn reads_see_the_snapshot_and_own_writes() {
    let mut s = new_store();
    let a = s.new_id().unwrap();
    set(&mut s, MAIN, a, 1);
    let mut tx = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
    set(&mut s, MAIN, a, 2);
    assert_eq!(s.read(&mut tx, a).map(|o| n_of(&o)), Some(1), "snapshot, not the newer commit");
    let mut own = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
    s.put(&mut own, item(a, 3)).unwrap();
    assert_eq!(s.read(&mut own, a).map(|o| n_of(&o)), Some(3));
    s.delete(&mut own, a).unwrap();
    assert_eq!(s.read(&mut own, a), None);
    assert_eq!(s.delete(&mut own, a), Err(StoreError::NotFound(a)));
    s.put(&mut own, item(a, 4)).unwrap();
    s.apply(own).unwrap();
    assert_eq!(s.version(MAIN, a), Some(5), "1, 2, then put, delete, put");
    assert_eq!(s.get(MAIN, a).map(n_of), Some(4));
    assert_eq!(s.apply(tx), Err(StoreError::Conflict(vec![a])), "the snapshot read is stale now");
}

#[test]
fn a_stale_read_fails_validation_even_without_writes_to_it() {
    let mut s = new_store();
    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(&mut s, MAIN, a, 1);
    set(&mut s, MAIN, b, 1);
    // Write skew: tx reads a and writes b; meanwhile a changes. Serializable means refuse.
    let mut tx = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
    let seen = s.read(&mut tx, a).map(|o| n_of(&o)).unwrap();
    s.put(&mut tx, item(b, seen + 1)).unwrap();
    set(&mut s, MAIN, a, 5);
    assert_eq!(s.apply(tx), Err(StoreError::Conflict(vec![a])));
}

#[test]
fn preconditions_are_checked_at_apply() {
    let mut s = new_store();
    let a = s.new_id().unwrap();
    set(&mut s, MAIN, a, 3);
    let meta = |n| TxMeta {
        preconditions: vec![Predicate::Field { object: a, field: "n".into(), cmp: Cmp::Gt, value: Value::Int(n) }],
        ..TxMeta::default()
    };
    let mut tx = s.begin(MAIN, Actor::User, meta(5)).unwrap();
    s.put(&mut tx, item(a, 0)).unwrap();
    let len = s.log().len();
    assert_eq!(s.apply(tx), Err(StoreError::PreconditionFailed(0)));
    assert_eq!(s.log().len(), len);
    let mut tx = s.begin(MAIN, Actor::User, meta(2)).unwrap();
    s.put(&mut tx, item(a, 0)).unwrap();
    assert!(s.apply(tx).is_ok());
}

#[test]
fn taint_propagates_through_derived_from_and_cannot_be_dropped() {
    let mut s = new_store();
    let (ext, clean, derived) = (s.new_id().unwrap(), s.new_id().unwrap(), s.new_id().unwrap());
    let mut tx = s.begin(MAIN, Actor::Adapter { name: Name::new("minio").unwrap() }, TxMeta::default()).unwrap();
    let mut o = item(ext, 1);
    o.provenance.origin = Origin::External {
        adapter: Name::new("minio").unwrap(),
        external_id: "s3://x".into(),
        fetched_at: Timestamp(1),
    };
    s.put(&mut tx, o).unwrap(); // declared clean, but external origin taints it
    s.put(&mut tx, item(clean, 2)).unwrap();
    s.apply(tx).unwrap();
    assert_eq!(s.get(MAIN, ext).unwrap().provenance.taint, Taint::External);
    assert_eq!(s.get(MAIN, clean).unwrap().provenance.taint, Taint::Clean);

    let mut tx = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
    let mut d = item(derived, 3);
    d.provenance.derived_from = BTreeSet::from([ObjectRef::latest(clean), ObjectRef::at(ext, 1)]);
    s.put(&mut tx, d).unwrap();
    s.apply(tx).unwrap();
    assert_eq!(s.get(MAIN, derived).unwrap().provenance.taint, Taint::External);

    let mut tx = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
    let mut d = item(s.new_id().unwrap(), 4);
    let missing = ObjectRef::at(clean, 9);
    d.provenance.derived_from = BTreeSet::from([missing]);
    assert_eq!(s.put(&mut tx, d), Err(StoreError::MissingInput(missing)));
}

#[test]
fn provenance_is_set_by_the_store() {
    let mut s = new_store();
    let a = s.new_id().unwrap();
    let task = Ulid::from_u128(77);
    let mut tx = s.begin(MAIN, Actor::Agent { task }, TxMeta::default()).unwrap();
    let mut o = item(a, 1);
    o.provenance.actor = Actor::User; // a lie the store must overwrite
    o.version = 42;
    s.put(&mut tx, o).unwrap();
    let id = tx.id();
    s.apply(tx).unwrap();
    let stored = s.get(MAIN, a).unwrap();
    assert_eq!(stored.version, 1);
    assert_eq!(stored.provenance.actor, Actor::Agent { task });
    assert_eq!(stored.provenance.tx, id);
}

/// One transaction of the concurrency property test: what it reads and writes, as indices
/// into the object set.
#[derive(Clone, Debug)]
struct TxPlan {
    reads: Vec<usize>,
    writes: Vec<usize>,
}

fn plans() -> impl Strategy<Value = (usize, Vec<TxPlan>, Vec<usize>)> {
    (2usize..6, 2usize..6).prop_flat_map(|(objects, txs)| {
        let plan = (proptest::collection::vec(0..objects, 0..4), proptest::collection::vec(0..objects, 0..3))
            .prop_map(|(reads, writes)| TxPlan { reads, writes });
        // Each transaction id appears twice: first occurrence = begin, second = apply.
        let order: Vec<usize> = (0..txs).flat_map(|t| [t, t]).collect();
        (Just(objects), proptest::collection::vec(plan, txs), Just(order).prop_shuffle())
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Interleaved transactions are accepted exactly when nothing they read or wrote changed
    /// since their snapshot, and the result equals running the accepted ones serially.
    #[test]
    fn concurrent_transactions_match_the_serial_model((objects, plans, order) in plans()) {
        let mut s = new_store();
        let ids: Vec<Ulid> = (0..objects).map(|_| s.new_id().unwrap()).collect();
        let mut setup = s.begin(MAIN, Actor::System, TxMeta::default()).unwrap();
        for (i, id) in ids.iter().enumerate() {
            s.put(&mut setup, item(*id, i as i64)).unwrap();
        }
        s.apply(setup).unwrap();

        // Model: version and value per object.
        let mut model: Vec<(u64, i64)> = (0..objects).map(|i| (1, i as i64)).collect();
        let mut open: BTreeMap<usize, (aos_branch::Tx, Vec<(u64, i64)>)> = BTreeMap::new();
        for t in order {
            if let Some((tx, snapshot)) = open.remove(&t) {
                let plan = &plans[t];
                let touched: BTreeSet<usize> = plan.reads.iter().chain(&plan.writes).copied().collect();
                let changed: Vec<Ulid> =
                    touched.iter().filter(|&&i| model[i].0 != snapshot[i].0).map(|&i| ids[i]).collect();
                let expected_conflict: BTreeSet<Ulid> = changed.iter().copied().collect();
                match s.apply(tx) {
                    Ok(_) => {
                        prop_assert!(changed.is_empty(), "accepted despite changes to {changed:?}");
                        let sum: i64 = plan.reads.iter().map(|&i| snapshot[i].1).sum();
                        for (k, &i) in plan.writes.iter().enumerate() {
                            model[i] = (model[i].0 + 1, sum + (t * 10 + k) as i64);
                        }
                    }
                    Err(StoreError::Conflict(got)) => {
                        prop_assert_eq!(got.into_iter().collect::<BTreeSet<_>>(), expected_conflict);
                    }
                    Err(e) => prop_assert!(false, "unexpected error {e:?}"),
                }
            } else {
                let mut tx = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
                let snapshot = model.clone();
                let plan = &plans[t];
                let mut sum = 0;
                for &i in &plan.reads {
                    sum += n_of(&s.read(&mut tx, ids[i]).unwrap());
                }
                for (k, &i) in plan.writes.iter().enumerate() {
                    s.put(&mut tx, item(ids[i], sum + (t * 10 + k) as i64)).unwrap();
                }
                open.insert(t, (tx, snapshot));
            }
        }
        for (i, id) in ids.iter().enumerate() {
            prop_assert_eq!(s.version(MAIN, *id), Some(model[i].0));
            prop_assert_eq!(s.get(MAIN, *id).map(n_of), Some(model[i].1));
        }
        assert_replay_matches(&s);
    }
}
