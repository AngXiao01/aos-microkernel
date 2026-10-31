//! Core conformance suite (SPEC §16.1): log, transactions, branches, undo.
//!
//! The suite only uses the public core API over a [`LogStorage`], so the same checks can
//! later run against the platform storage server through the IPC adapter (§B10). This
//! crate holds the shared fixtures; the checks are in `tests/`.

use std::collections::BTreeMap;

use aos_branch::{BranchId, Env, Status, Store};
use aos_log::{LogStorage, MemStorage};
use aos_types::{Actor, Object, Origin, Provenance, Sensitivity, Taint, Timestamp, Ulid, Value};

/// Deterministic clock (1 ms per call) and entropy (xorshift).
#[derive(Clone, Debug)]
pub struct TestEnv {
    now: u64,
    rng: u64,
}

impl TestEnv {
    pub fn new(seed: u64) -> TestEnv {
        TestEnv { now: 1_700_000_000_000, rng: seed | 1 }
    }
}

impl Env for TestEnv {
    fn now(&mut self) -> Timestamp {
        self.now += 1;
        Timestamp(self.now)
    }

    fn entropy(&mut self) -> [u8; 10] {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let mut out = [0u8; 10];
        out[..8].copy_from_slice(&self.rng.to_be_bytes());
        out
    }
}

pub type MemStore = Store<MemStorage, TestEnv>;

pub fn new_store() -> MemStore {
    Store::open(MemStorage::new(), TestEnv::new(7), None).expect("empty log opens")
}

pub const ITEM: &str = "test/Item@1";

/// A test object with one integer field `n`. Version, actor and tx are set by the store.
pub fn item(id: Ulid, n: i64) -> Object {
    let mut fields = BTreeMap::new();
    fields.insert("n".to_string(), Value::Int(n));
    Object {
        id,
        type_id: ITEM.parse().unwrap(),
        version: 0,
        fields,
        blobs: Default::default(),
        provenance: Provenance {
            actor: Actor::System,
            origin: Origin::Internal,
            taint: Taint::Clean,
            derived_from: Default::default(),
            tx: Ulid::from_u128(0),
        },
        sensitivity: Sensitivity::Internal,
        extra: BTreeMap::new(),
    }
}

pub fn n_of(object: &Object) -> i64 {
    match object.fields.get("n") {
        Some(Value::Int(n)) => *n,
        other => panic!("field n is {other:?}"),
    }
}

/// Values of `n` for every live object on `branch`.
pub fn values(store: &Store<impl LogStorage, impl Env>, branch: BranchId) -> BTreeMap<Ulid, i64> {
    store.objects(branch).iter().map(|(id, o)| (*id, n_of(o))).collect()
}

/// Reopens the store from a copy of its storage, checked against its anchor.
pub fn reopen<S: LogStorage + Clone>(store: &Store<S, TestEnv>) -> Store<S, TestEnv> {
    Store::open(store.log().storage().clone(), TestEnv::new(99), Some(store.anchor()))
        .unwrap_or_else(|e| panic!("replay failed: {e:?}"))
}

/// Replaying the log reproduces every branch's objects and every fork's status.
pub fn assert_replay_matches<S: LogStorage + Clone>(store: &Store<S, TestEnv>) {
    let replayed = reopen(store);
    assert_eq!(replayed.objects(BranchId::Main), store.objects(BranchId::Main), "main differs after replay");
    let forks: Vec<(Ulid, Status)> = store.forks().map(|(id, s)| (id, s.clone())).collect();
    let replayed_forks: Vec<(Ulid, Status)> = replayed.forks().map(|(id, s)| (id, s.clone())).collect();
    assert_eq!(replayed_forks, forks, "fork statuses differ after replay");
    for (id, _) in forks {
        let b = BranchId::Fork(id);
        assert_eq!(replayed.objects(b), store.objects(b), "{b} differs after replay");
    }
}

/// Commits a write of `n` to object `id` on `branch` in its own transaction.
pub fn set<S: LogStorage>(store: &mut Store<S, TestEnv>, branch: BranchId, id: Ulid, n: i64) -> Ulid
where
    S::Error: std::fmt::Debug,
{
    let mut tx = store.begin(branch, Actor::User, Default::default()).unwrap();
    store.put(&mut tx, item(id, n)).unwrap();
    store.apply(tx).unwrap().tx
}
