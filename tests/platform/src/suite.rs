//! The deterministic half of the conformance suite (SPEC §16.1: log, transactions,
//! branches, undo), driven through whatever [`LogStorage`] the caller opened.
//! The 10⁴-case property tests stay on `MemStorage`; they exercise the same `Store`.

use std::collections::{BTreeMap, BTreeSet};

use aos_branch::{BranchId, ChangeKind, Cmp, Predicate, Rejection, Status, Store, StoreError, TxMeta};
use aos_conformance::{TestEnv, assert_replay_matches, item, n_of, set, values};
use aos_log::LogStorage;
use aos_types::{Actor, Name, ObjectRef, Origin, Taint, Timestamp, Ulid, Value};

const MAIN: BranchId = BranchId::Main;

fn fork_id(b: BranchId) -> Ulid {
    match b {
        BranchId::Fork(id) => id,
        BranchId::Main => panic!("not a fork"),
    }
}

pub fn run<S>(s: &mut Store<S, TestEnv>)
where
    S: LogStorage + Clone,
    S::Error: std::fmt::Debug + PartialEq,
{
    // Log: a chain of commits, a fork and a revert replays to the same state.
    let ids: Vec<_> = (0..3).map(|_| s.new_id().unwrap()).collect();
    for (i, id) in ids.iter().enumerate() {
        set(s, MAIN, *id, i as i64);
    }
    let fork = s.fork(Actor::User).unwrap();
    set(s, fork, ids[0], 100);
    let f = fork_id(fork);
    s.submit(f, Actor::System).unwrap();
    s.commit(f, Actor::User).unwrap();
    let tx = set(s, MAIN, ids[1], 7);
    s.revert(MAIN, tx, Actor::User).unwrap();
    let mut prev = aos_log::GENESIS;
    for seq in 0..s.log().len() {
        let e = s.log().read(seq).unwrap();
        assert_eq!(e.prev_hash, prev, "chain link at {seq}");
        prev = e.hash;
    }
    assert_eq!(prev, s.anchor().head);
    assert_replay_matches(s);

    // Transactions.
    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(s, MAIN, a, 1);
    set(s, MAIN, b, 1);
    let log_len = s.log().len();
    let mut tx = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
    s.put(&mut tx, item(a, 10)).unwrap();
    s.put(&mut tx, item(b, 10)).unwrap();
    set(s, MAIN, b, 2);
    assert_eq!(s.apply(tx), Err(StoreError::Conflict(vec![b])));
    assert_eq!(values(s, MAIN).get(&a).copied(), Some(1));
    assert_eq!(values(s, MAIN).get(&b).copied(), Some(2));
    assert_eq!(s.log().len(), log_len + 1);

    let a = s.new_id().unwrap();
    set(s, MAIN, a, 1);
    let mut tx = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
    set(s, MAIN, a, 2);
    assert_eq!(s.read(&mut tx, a).map(|o| n_of(&o)), Some(1));
    let mut own = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
    s.put(&mut own, item(a, 3)).unwrap();
    assert_eq!(s.read(&mut own, a).map(|o| n_of(&o)), Some(3));
    s.apply(own).unwrap();
    assert_eq!(s.apply(tx), Err(StoreError::Conflict(vec![a])));

    let a = s.new_id().unwrap();
    set(s, MAIN, a, 3);
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

    let (ext, clean, derived) = (s.new_id().unwrap(), s.new_id().unwrap(), s.new_id().unwrap());
    let mut tx = s.begin(MAIN, Actor::Adapter { name: Name::new("minio").unwrap() }, TxMeta::default()).unwrap();
    let mut o = item(ext, 1);
    o.provenance.origin = Origin::External {
        adapter: Name::new("minio").unwrap(),
        external_id: "s3://x".into(),
        fetched_at: Timestamp(1),
    };
    s.put(&mut tx, o).unwrap();
    s.put(&mut tx, item(clean, 2)).unwrap();
    s.apply(tx).unwrap();
    assert_eq!(s.get(MAIN, ext).unwrap().provenance.taint, Taint::External);
    let mut tx = s.begin(MAIN, Actor::User, TxMeta::default()).unwrap();
    let mut d = item(derived, 3);
    d.provenance.derived_from = BTreeSet::from([ObjectRef::latest(clean), ObjectRef::at(ext, 1)]);
    s.put(&mut tx, d).unwrap();
    s.apply(tx).unwrap();
    assert_eq!(s.get(MAIN, derived).unwrap().provenance.taint, Taint::External);

    // Branches.
    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(s, MAIN, a, 1);
    let f1 = s.fork(Actor::User).unwrap();
    let f2 = s.fork(Actor::User).unwrap();
    set(s, f1, a, 10);
    set(s, f1, b, 20);
    set(s, f2, a, 30);
    set(s, MAIN, a, 2);
    assert_eq!(values(s, MAIN).get(&a).copied(), Some(2));
    assert_eq!(values(s, f1).get(&a).copied(), Some(10));
    assert_eq!(values(s, f1).get(&b).copied(), Some(20));
    assert_eq!(values(s, f2).get(&a).copied(), Some(30));
    assert_eq!(values(s, f2).get(&b), None, "forks do not see each other");
    assert_replay_matches(s);

    let (a, b, c) = (s.new_id().unwrap(), s.new_id().unwrap(), s.new_id().unwrap());
    set(s, MAIN, a, 1);
    set(s, MAIN, b, 1);
    let f = s.fork(Actor::User).unwrap();
    set(s, f, a, 10);
    set(s, MAIN, b, 2);
    set(s, MAIN, c, 3);
    s.rebase(fork_id(f), Actor::User).unwrap();
    assert_eq!(values(s, f).get(&a).copied(), Some(10));
    assert_eq!(values(s, f).get(&b).copied(), Some(2));
    assert_eq!(values(s, f).get(&c).copied(), Some(3));
    set(s, MAIN, a, 5);
    assert_eq!(s.rebase(fork_id(f), Actor::User), Err(StoreError::Conflict(vec![a])));
    assert_replay_matches(s);

    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(s, MAIN, a, 1);
    let f = s.fork(Actor::Agent { task: Ulid::from_u128(5) }).unwrap();
    set(s, f, a, 10);
    set(s, f, a, 11);
    set(s, f, b, 20);
    let id = fork_id(f);
    assert!(matches!(s.commit(id, Actor::User), Err(StoreError::WrongStatus(_))));
    s.submit(id, Actor::System).unwrap();
    s.commit(id, Actor::User).unwrap();
    assert_eq!(values(s, MAIN).get(&a).copied(), Some(11));
    assert_eq!(values(s, MAIN).get(&b).copied(), Some(20));
    assert_eq!(s.version(MAIN, a), Some(3));
    assert_eq!(s.resolve(MAIN, ObjectRef::at(a, 2)).map(n_of), Some(10));
    assert!(matches!(s.status(id), Some(Status::Committed { .. })));
    assert_replay_matches(s);

    let (budget, out) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(s, MAIN, budget, 3);
    let f = s.fork(Actor::User).unwrap();
    let id = fork_id(f);
    let guarded_meta = TxMeta {
        preconditions: vec![Predicate::Field { object: budget, field: "n".into(), cmp: Cmp::Gt, value: Value::Int(0) }],
        ..TxMeta::default()
    };
    let mut tx = s.begin(f, Actor::User, guarded_meta).unwrap();
    s.put(&mut tx, item(out, 1)).unwrap();
    let guarded = tx.id();
    s.apply(tx).unwrap();
    s.submit(id, Actor::System).unwrap();
    set(s, MAIN, budget, 0);
    let rejection = Rejection::Precondition { tx: guarded, index: 0 };
    assert_eq!(s.commit(id, Actor::User), Err(StoreError::Rejected(rejection.clone())));
    assert_eq!(s.status(id), Some(&Status::Review { rejection: Some(rejection) }));
    set(s, MAIN, budget, 2);
    s.commit(id, Actor::User).unwrap();
    assert_eq!(values(s, MAIN).get(&out).copied(), Some(1));
    assert_replay_matches(s);

    let a = s.new_id().unwrap();
    set(s, MAIN, a, 1);
    let f = s.fork(Actor::User).unwrap();
    set(s, f, a, 10);
    set(s, MAIN, a, 2);
    s.submit(fork_id(f), Actor::System).unwrap();
    assert_eq!(s.commit(fork_id(f), Actor::User), Err(StoreError::Rejected(Rejection::Conflict(vec![a]))));

    let ids: Vec<Ulid> = (0..5).map(|_| s.new_id().unwrap()).collect();
    for (i, id) in ids.iter().enumerate() {
        set(s, MAIN, *id, i as i64);
    }
    let f = s.fork(Actor::User).unwrap();
    set(s, f, ids[0], 100);
    set(s, f, ids[1], 1);
    let mut tx = s.begin(f, Actor::User, TxMeta::default()).unwrap();
    s.delete(&mut tx, ids[2]).unwrap();
    let created = s.new_id().unwrap();
    s.put(&mut tx, item(created, 7)).unwrap();
    s.apply(tx).unwrap();
    let diff = s.diff(fork_id(f)).unwrap();
    let t = &diff.types[&aos_conformance::ITEM.parse().unwrap()];
    assert_eq!((t.created, t.updated, t.deleted), (1, 1, 1));
    let kinds: BTreeMap<Ulid, ChangeKind> = t.objects.iter().map(|c| (c.id, c.kind)).collect();
    assert_eq!(kinds.get(&ids[0]), Some(&ChangeKind::Updated));
    assert_eq!(kinds.get(&ids[2]), Some(&ChangeKind::Deleted));
    assert_eq!(kinds.get(&created), Some(&ChangeKind::Created));

    // Undo.
    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(s, MAIN, a, 1);
    let mut tx = s.begin(MAIN, Actor::Agent { task: Ulid::from_u128(1) }, TxMeta::default()).unwrap();
    s.put(&mut tx, item(a, 2)).unwrap();
    s.put(&mut tx, item(b, 3)).unwrap();
    let t = s.apply(tx).unwrap().tx;
    let r = s.revert(MAIN, t, Actor::User).unwrap().tx;
    assert_eq!(values(s, MAIN).get(&a).copied(), Some(1));
    assert!(!values(s, MAIN).contains_key(&b));
    assert_eq!(s.version(MAIN, a), Some(3));
    s.revert(MAIN, r, Actor::User).unwrap();
    assert_eq!(values(s, MAIN).get(&a).copied(), Some(2));
    assert_eq!(values(s, MAIN).get(&b).copied(), Some(3));
    assert_replay_matches(s);

    let a = s.new_id().unwrap();
    set(s, MAIN, a, 1);
    let t = set(s, MAIN, a, 2);
    set(s, MAIN, a, 3);
    assert_eq!(s.revert(MAIN, t, Actor::User), Err(StoreError::Conflict(vec![a])));

    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(s, MAIN, a, 1);
    let f = s.fork(Actor::User).unwrap();
    let fid = fork_id(f);
    set(s, f, a, 10);
    set(s, f, b, 20);
    s.submit(fid, Actor::System).unwrap();
    let merge = s.commit(fid, Actor::User).unwrap().tx;
    s.revert(MAIN, merge, Actor::User).unwrap();
    assert_eq!(values(s, MAIN).get(&a).copied(), Some(1));
    assert!(!values(s, MAIN).contains_key(&b));
    assert_replay_matches(s);
}
