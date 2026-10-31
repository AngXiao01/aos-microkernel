//! §16.1 分支：分叉 O(1)；分支隔离；变基正确；前置条件在提交时重新评估。

use std::collections::BTreeMap;
use std::time::Instant;

use aos_branch::{BranchId, ChangeKind, Cmp, Predicate, Rejection, Status, StoreError, TxMeta};
use aos_conformance::{assert_replay_matches, item, new_store, reopen, set, values};
use aos_types::{Actor, Ulid, Value};

const MAIN: BranchId = BranchId::Main;

fn fork_id(b: BranchId) -> Ulid {
    match b {
        BranchId::Fork(id) => id,
        BranchId::Main => panic!("not a fork"),
    }
}

#[test]
fn forking_copies_nothing() {
    let mut s = new_store();
    let mut tx = s.begin(MAIN, Actor::System, TxMeta::default()).unwrap();
    for i in 0..100_000 {
        let id = s.new_id().unwrap();
        s.put(&mut tx, item(id, i)).unwrap();
    }
    s.apply(tx).unwrap();
    // Best of five: the first allocations after freeing the large transaction pay for the
    // allocator returning and re-faulting memory, which says nothing about forking.
    let mut fastest = std::time::Duration::MAX;
    let mut fork = BranchId::Main;
    for _ in 0..5 {
        let start = Instant::now();
        fork = s.fork(Actor::User).unwrap();
        fastest = fastest.min(start.elapsed());
    }
    assert!(fastest.as_millis() < 10, "fork took {fastest:?} with 1e5 objects (§7.8: < 10 ms)");
    assert_eq!(s.diff(fork_id(fork)).unwrap().types.len(), 0);
    assert_eq!(s.objects(fork).len(), 100_000);
}

#[test]
fn branches_are_isolated() {
    let mut s = new_store();
    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(&mut s, MAIN, a, 1);
    let f1 = s.fork(Actor::User).unwrap();
    let f2 = s.fork(Actor::User).unwrap();
    set(&mut s, f1, a, 10);
    set(&mut s, f1, b, 20);
    set(&mut s, f2, a, 30);
    set(&mut s, MAIN, a, 2);

    assert_eq!(values(&s, MAIN), BTreeMap::from([(a, 2)]), "fork writes stay off main");
    assert_eq!(values(&s, f1), BTreeMap::from([(a, 10), (b, 20)]));
    assert_eq!(values(&s, f2), BTreeMap::from([(a, 30)]), "forks do not see each other");
    let f3 = s.fork(Actor::User).unwrap();
    assert_eq!(values(&s, f3), BTreeMap::from([(a, 2)]), "a fork sees main as of its base");
    set(&mut s, MAIN, b, 5);
    assert_eq!(values(&s, f3), BTreeMap::from([(a, 2)]), "later main writes stay invisible until rebase");
    assert_replay_matches(&s);
}

#[test]
fn rebase_moves_the_base_and_detects_conflicts() {
    let mut s = new_store();
    let (a, b, c) = (s.new_id().unwrap(), s.new_id().unwrap(), s.new_id().unwrap());
    set(&mut s, MAIN, a, 1);
    set(&mut s, MAIN, b, 1);
    let f = s.fork(Actor::User).unwrap();
    set(&mut s, f, a, 10);
    set(&mut s, MAIN, b, 2);
    set(&mut s, MAIN, c, 3);
    s.rebase(fork_id(f), Actor::User).unwrap();
    assert_eq!(values(&s, f), BTreeMap::from([(a, 10), (b, 2), (c, 3)]));

    set(&mut s, MAIN, a, 5); // main now changed an object the fork wrote
    assert_eq!(s.rebase(fork_id(f), Actor::User), Err(StoreError::Conflict(vec![a])));
    assert_eq!(values(&s, f), BTreeMap::from([(a, 10), (b, 2), (c, 3)]), "a refused rebase changes nothing");
    assert_replay_matches(&s);
}

#[test]
fn commit_merges_every_version_as_one_transaction() {
    let mut s = new_store();
    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(&mut s, MAIN, a, 1);
    let f = s.fork(Actor::Agent { task: Ulid::from_u128(5) }).unwrap();
    set(&mut s, f, a, 10);
    set(&mut s, f, a, 11);
    set(&mut s, f, b, 20);
    let id = fork_id(f);
    assert_eq!(s.commit(id, Actor::User), Err(StoreError::WrongStatus(f)), "only reviewed branches commit");
    s.submit(id, Actor::System).unwrap();
    let main_len_before = s.log().len();
    let receipt = s.commit(id, Actor::User).unwrap();
    assert_eq!(s.log().len(), main_len_before + 1);
    assert_eq!(values(&s, MAIN), BTreeMap::from([(a, 11), (b, 20)]));
    assert_eq!(s.version(MAIN, a), Some(3), "versions stay dense on main");
    assert_eq!(s.resolve(MAIN, aos_types::ObjectRef::at(a, 2)).map(aos_conformance::n_of), Some(10));
    assert!(matches!(s.status(id), Some(Status::Committed { merge_seq }) if Some(*merge_seq) == receipt.seq));
    assert!(s.begin(f, Actor::User, TxMeta::default()).is_err(), "a committed branch is closed");
    assert_replay_matches(&s);
}

#[test]
fn commit_reevaluates_preconditions_on_the_rebased_branch() {
    let mut s = new_store();
    let (budget, out) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(&mut s, MAIN, budget, 3);
    let f = s.fork(Actor::User).unwrap();
    let id = fork_id(f);
    let meta = TxMeta {
        preconditions: vec![Predicate::Field { object: budget, field: "n".into(), cmp: Cmp::Gt, value: Value::Int(0) }],
        ..TxMeta::default()
    };
    let mut tx = s.begin(f, Actor::User, meta).unwrap();
    s.put(&mut tx, item(out, 1)).unwrap();
    let guarded = tx.id();
    s.apply(tx).unwrap(); // holds now: budget is 3
    s.submit(id, Actor::System).unwrap();

    set(&mut s, MAIN, budget, 0); // main changes something the fork only read
    let rejection = Rejection::Precondition { tx: guarded, index: 0 };
    assert_eq!(s.commit(id, Actor::User), Err(StoreError::Rejected(rejection.clone())));
    assert_eq!(s.status(id), Some(&Status::Review { rejection: Some(rejection.clone()) }));
    assert_eq!(values(&s, MAIN), BTreeMap::from([(budget, 0)]));
    assert_eq!(reopen(&s).status(id), Some(&Status::Review { rejection: Some(rejection) }), "the reason is logged");

    set(&mut s, MAIN, budget, 2);
    s.commit(id, Actor::User).unwrap();
    assert_eq!(values(&s, MAIN), BTreeMap::from([(budget, 2), (out, 1)]));
    assert_replay_matches(&s);
}

#[test]
fn commit_refuses_write_conflicts() {
    let mut s = new_store();
    let a = s.new_id().unwrap();
    set(&mut s, MAIN, a, 1);
    let f = s.fork(Actor::User).unwrap();
    set(&mut s, f, a, 10);
    set(&mut s, MAIN, a, 2);
    s.submit(fork_id(f), Actor::System).unwrap();
    assert_eq!(s.commit(fork_id(f), Actor::User), Err(StoreError::Rejected(Rejection::Conflict(vec![a]))));
    assert_eq!(values(&s, MAIN), BTreeMap::from([(a, 2)]));
}

#[test]
fn lifecycle_transitions() {
    let mut s = new_store();
    let f = s.fork(Actor::User).unwrap();
    let id = fork_id(f);
    assert_eq!(s.reopen(id, None, Actor::User), Err(StoreError::WrongStatus(f)));
    s.submit(id, Actor::System).unwrap();
    assert!(s.begin(f, Actor::User, TxMeta::default()).is_err(), "no writes while in review");
    s.reopen(id, Some("relabel row 3 too".into()), Actor::User).unwrap();
    assert_eq!(s.status(id), Some(&Status::Open { note: Some("relabel row 3 too".into()) }));
    s.discard(id, Actor::User).unwrap();
    assert_eq!(s.submit(id, Actor::System), Err(StoreError::WrongStatus(f)));
    assert_eq!(s.discard(id, Actor::User), Err(StoreError::WrongStatus(f)));
    assert_eq!(s.status(Ulid::from_u128(1)), None);
    assert_replay_matches(&s);
}

#[test]
fn diff_groups_changes_by_type_with_field_counts() {
    let mut s = new_store();
    let ids: Vec<Ulid> = (0..5).map(|_| s.new_id().unwrap()).collect();
    for (i, id) in ids.iter().enumerate() {
        set(&mut s, MAIN, *id, i as i64);
    }
    let f = s.fork(Actor::User).unwrap();
    set(&mut s, f, ids[0], 100); // updated
    set(&mut s, f, ids[1], 1); // rewritten with identical content: not a change
    let mut tx = s.begin(f, Actor::User, TxMeta::default()).unwrap();
    s.delete(&mut tx, ids[2]).unwrap();
    let created = s.new_id().unwrap();
    s.put(&mut tx, item(created, 7)).unwrap();
    let temp = s.new_id().unwrap();
    s.put(&mut tx, item(temp, 8)).unwrap();
    s.delete(&mut tx, temp).unwrap(); // created and deleted inside the fork: no change
    s.apply(tx).unwrap();

    let diff = s.diff(fork_id(f)).unwrap();
    let t = &diff.types[&aos_conformance::ITEM.parse().unwrap()];
    assert_eq!((t.created, t.updated, t.deleted), (1, 1, 1));
    assert_eq!(t.field_counts, BTreeMap::from([("n".to_string(), 1)]));
    let kinds: BTreeMap<Ulid, ChangeKind> = t.objects.iter().map(|c| (c.id, c.kind)).collect();
    assert_eq!(
        kinds,
        BTreeMap::from([(ids[0], ChangeKind::Updated), (ids[2], ChangeKind::Deleted), (created, ChangeKind::Created)])
    );
}
