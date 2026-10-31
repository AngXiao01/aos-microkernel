//! §16.1 撤销：对任意内部事务序列做随机撤销，状态与重放结果一致（属性测试）。

use std::collections::{BTreeMap, BTreeSet};

use aos_branch::{BranchId, Status, StoreError, TxMeta};
use aos_conformance::{MemStore, assert_replay_matches, item, n_of, new_store, set, values};
use aos_types::{Actor, Ulid};
use proptest::prelude::*;

const MAIN: BranchId = BranchId::Main;

#[test]
fn revert_restores_and_revert_of_revert_reapplies() {
    let mut s = new_store();
    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    set(&mut s, MAIN, a, 1);
    let mut tx = s.begin(MAIN, Actor::Agent { task: Ulid::from_u128(1) }, TxMeta::default()).unwrap();
    s.put(&mut tx, item(a, 2)).unwrap();
    s.put(&mut tx, item(b, 3)).unwrap();
    let t = s.apply(tx).unwrap().tx;

    let r = s.revert(MAIN, t, Actor::User).unwrap().tx;
    assert_eq!(values(&s, MAIN), BTreeMap::from([(a, 1)]), "a restored, b (created by t) gone");
    assert_eq!(s.version(MAIN, a), Some(3), "undo appends; history is never rewritten");
    assert_eq!(s.get(MAIN, a).unwrap().provenance.actor, Actor::User);

    assert!(matches!(s.revert(MAIN, t, Actor::User), Err(StoreError::Conflict(_))), "reverting twice conflicts");
    s.revert(MAIN, r, Actor::User).unwrap();
    assert_eq!(values(&s, MAIN), BTreeMap::from([(a, 2), (b, 3)]));
    assert_replay_matches(&s);
}

#[test]
fn revert_refuses_to_clobber_later_writes() {
    let mut s = new_store();
    let a = s.new_id().unwrap();
    set(&mut s, MAIN, a, 1);
    let t = set(&mut s, MAIN, a, 2);
    set(&mut s, MAIN, a, 3);
    assert_eq!(s.revert(MAIN, t, Actor::User), Err(StoreError::Conflict(vec![a])));
    assert_eq!(values(&s, MAIN), BTreeMap::from([(a, 3)]));
}

#[test]
fn a_merge_reverts_as_a_unit_and_main_history_is_revertible_from_a_fork() {
    let mut s = new_store();
    let (a, b) = (s.new_id().unwrap(), s.new_id().unwrap());
    let t0 = set(&mut s, MAIN, a, 1);
    let f = s.fork(Actor::User).unwrap();
    let BranchId::Fork(fid) = f else { unreachable!() };
    set(&mut s, f, a, 10);
    set(&mut s, f, b, 20);
    s.submit(fid, Actor::System).unwrap();
    let merge = s.commit(fid, Actor::User).unwrap().tx;
    s.revert(MAIN, merge, Actor::User).unwrap();
    assert_eq!(values(&s, MAIN), BTreeMap::from([(a, 1)]));

    let g = s.fork(Actor::User).unwrap();
    assert_eq!(s.revert(MAIN, Ulid::from_u128(12345), Actor::User), Err(StoreError::UnknownTx(Ulid::from_u128(12345))));
    let gt = set(&mut s, g, b, 5);
    assert_eq!(s.revert(MAIN, gt, Actor::User), Err(StoreError::NotVisible(gt)), "main cannot revert fork history");
    assert!(matches!(s.revert(g, t0, Actor::User), Err(StoreError::Conflict(_))), "a changed since t0");
    let late = set(&mut s, MAIN, b, 9);
    assert_eq!(s.revert(g, late, Actor::User), Err(StoreError::NotVisible(late)), "after the fork's base");
    assert_replay_matches(&s);
}

const OBJECTS: usize = 4;

#[derive(Clone, Debug)]
enum Step {
    Set { fork: bool, obj: usize, n: i64 },
    Delete { fork: bool, obj: usize },
    Revert { fork: bool, pick: usize },
    Fork,
    Commit,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => (any::<bool>(), 0..OBJECTS, -50i64..50).prop_map(|(fork, obj, n)| Step::Set { fork, obj, n }),
        1 => (any::<bool>(), 0..OBJECTS).prop_map(|(fork, obj)| Step::Delete { fork, obj }),
        3 => (any::<bool>(), any::<usize>()).prop_map(|(fork, pick)| Step::Revert { fork, pick }),
        1 => Just(Step::Fork),
        1 => Just(Step::Commit),
    ]
}

/// (version, value) of each test object on a branch.
type Snapshot = Vec<(Option<u64>, Option<i64>)>;

fn snapshot(s: &MemStore, branch: BranchId, ids: &[Ulid]) -> Snapshot {
    ids.iter().map(|id| (s.version(branch, *id), s.get(branch, *id).map(n_of))).collect()
}

/// What a logged transaction did, observed from outside the store.
struct Logged {
    branch: BranchId,
    seq: u64,
    /// (object index, value before, version after) for every object whose version moved.
    written: Vec<(usize, Option<i64>, u64)>,
}

fn observed(branch: BranchId, seq: Option<u64>, before: &Snapshot, after: &Snapshot) -> Option<Logged> {
    let written: Vec<_> = (0..before.len())
        .filter(|&i| before[i].0 != after[i].0)
        .map(|i| (i, before[i].1, after[i].0.unwrap()))
        .collect();
    seq.map(|seq| Logged { branch, seq, written })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Random histories with random reverts on main and a fork: every revert does exactly
    /// what the model predicts, and the final state equals a replay of the log.
    #[test]
    fn random_reverts_match_the_model_and_replay(steps in proptest::collection::vec(step(), 1..30)) {
        let mut s = new_store();
        let ids: Vec<Ulid> = (0..OBJECTS).map(|_| s.new_id().unwrap()).collect();
        let mut fork: Option<(Ulid, u64)> = None; // (id, base)
        let mut log: Vec<(Ulid, Logged)> = Vec::new();

        for step in steps {
            let branch_of = |on_fork: bool| match (on_fork, fork) {
                (true, Some((f, _))) => Some(BranchId::Fork(f)),
                (true, None) => None,
                (false, _) => Some(MAIN),
            };
            let writable = |s: &MemStore, b: BranchId| match b {
                BranchId::Main => true,
                BranchId::Fork(f) => matches!(s.status(f), Some(Status::Open { .. })),
            };
            match step {
                Step::Set { fork: f, obj, n } => {
                    let Some(b) = branch_of(f) else { continue };
                    if !writable(&s, b) { continue }
                    let before = snapshot(&s, b, &ids);
                    let mut tx = s.begin(b, Actor::User, TxMeta::default()).unwrap();
                    s.put(&mut tx, item(ids[obj], n)).unwrap();
                    let r = s.apply(tx).unwrap();
                    let after = snapshot(&s, b, &ids);
                    log.extend(observed(b, r.seq, &before, &after).map(|l| (r.tx, l)));
                }
                Step::Delete { fork: f, obj } => {
                    let Some(b) = branch_of(f) else { continue };
                    if !writable(&s, b) || s.get(b, ids[obj]).is_none() { continue }
                    let before = snapshot(&s, b, &ids);
                    let mut tx = s.begin(b, Actor::User, TxMeta::default()).unwrap();
                    s.delete(&mut tx, ids[obj]).unwrap();
                    let r = s.apply(tx).unwrap();
                    let after = snapshot(&s, b, &ids);
                    log.extend(observed(b, r.seq, &before, &after).map(|l| (r.tx, l)));
                }
                Step::Revert { fork: f, pick } => {
                    let Some(b) = branch_of(f) else { continue };
                    if log.is_empty() || !writable(&s, b) { continue }
                    let (target, t) = &log[pick % log.len()];
                    let visible = t.branch == b
                        || matches!((t.branch, b, fork), (BranchId::Main, BranchId::Fork(_), Some((_, base))) if t.seq < base);
                    let before = snapshot(&s, b, &ids);
                    let result = s.revert(b, *target, Actor::User);
                    if !visible {
                        prop_assert_eq!(result, Err(StoreError::NotVisible(*target)));
                        continue;
                    }
                    let conflicts: BTreeSet<Ulid> =
                        t.written.iter().filter(|(i, _, v)| before[*i].0 != Some(*v)).map(|(i, _, _)| ids[*i]).collect();
                    match result {
                        Ok(r) => {
                            prop_assert!(conflicts.is_empty(), "revert accepted despite later writes to {conflicts:?}");
                            let after = snapshot(&s, b, &ids);
                            for (i, value_before, _) in &t.written {
                                prop_assert_eq!(after[*i].1, *value_before, "object {} not restored", i);
                            }
                            let untouched: BTreeSet<usize> = (0..OBJECTS).filter(|i| !t.written.iter().any(|w| w.0 == *i)).collect();
                            for i in untouched {
                                prop_assert_eq!(&after[i], &before[i], "revert touched object {}", i);
                            }
                            log.extend(observed(b, r.seq, &before, &after).map(|l| (r.tx, l)));
                        }
                        Err(StoreError::Conflict(got)) => {
                            prop_assert_eq!(got.into_iter().collect::<BTreeSet<_>>(), conflicts);
                        }
                        Err(e) => prop_assert!(false, "unexpected revert error {e:?}"),
                    }
                }
                Step::Fork => {
                    if fork.is_some() { continue }
                    let base = s.log().len();
                    let BranchId::Fork(id) = s.fork(Actor::User).unwrap() else { unreachable!() };
                    fork = Some((id, base));
                }
                Step::Commit => {
                    let Some((f, _)) = fork else { continue };
                    if !writable(&s, BranchId::Fork(f)) { continue }
                    s.submit(f, Actor::System).unwrap();
                    let before = snapshot(&s, MAIN, &ids);
                    if let Ok(r) = s.commit(f, Actor::User) {
                        let after = snapshot(&s, MAIN, &ids);
                        log.extend(observed(MAIN, r.seq, &before, &after).map(|l| (r.tx, l)));
                    }
                }
            }
        }
        assert_replay_matches(&s);
    }
}
