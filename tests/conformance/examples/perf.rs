//! SPEC §7.8 performance targets on the in-memory backend:
//! fork < 10 ms; commit a 10k-write transaction < 2 s; diff a branch over a 1M-sample
//! dataset < 5 s; revert a 10k-write transaction < 2 s.
//!
//! cargo run --release -p aos-conformance --example perf

use std::time::{Duration, Instant};

use aos_branch::{BranchId, TxMeta};
use aos_conformance::{item, new_store};
use aos_types::{Actor, Ulid, Value};

fn timed<T>(label: &str, target: Duration, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    let took = start.elapsed();
    let verdict = if took < target { "ok" } else { "MISSED" };
    println!("{label:<48} {took:>12.3?}  (target < {target:?}) {verdict}");
    out
}

fn main() {
    let mut s = new_store();
    let samples = 1_000_000;
    let mut ids: Vec<Ulid> = Vec::with_capacity(samples);
    let setup = Instant::now();
    for _ in 0..samples / 100_000 {
        let mut tx = s.begin(BranchId::Main, Actor::System, TxMeta::default()).unwrap();
        for i in 0..100_000 {
            let id = s.new_id().unwrap();
            s.put(&mut tx, item(id, i)).unwrap();
            ids.push(id);
        }
        s.apply(tx).unwrap();
    }
    println!("setup: {} samples on main in {:.1?}", samples, setup.elapsed());

    let fork = timed("fork (1M objects on main)", Duration::from_millis(10), || s.fork(Actor::User).unwrap());
    let BranchId::Fork(fid) = fork else { unreachable!() };

    let big = timed("commit tx with 10k writes (on the fork)", Duration::from_secs(2), || {
        let mut tx = s.begin(fork, Actor::User, TxMeta::default()).unwrap();
        for id in &ids[..10_000] {
            s.put(&mut tx, item(*id, -1)).unwrap();
        }
        s.apply(tx).unwrap().tx
    });

    // The §15.1 shape: dedupe deletes 3,214 samples, relabel touches 118.
    let mut tx = s.begin(fork, Actor::User, TxMeta::default()).unwrap();
    for id in &ids[10_000..13_214] {
        s.delete(&mut tx, *id).unwrap();
    }
    for id in &ids[20_000..20_118] {
        let mut o = s.read(&mut tx, *id).unwrap();
        o.fields.insert("label".into(), Value::text("fall"));
        s.put(&mut tx, o).unwrap();
    }
    s.apply(tx).unwrap();
    let diff = timed("diff of the fork over 1M samples", Duration::from_secs(5), || s.diff(fid).unwrap());
    let t = diff.types.values().next().unwrap();
    println!("  diff: {} updated, {} deleted, fields {:?}", t.updated, t.deleted, t.field_counts);

    timed("revert the 10k-write transaction", Duration::from_secs(2), || s.revert(fork, big, Actor::User).unwrap());
}
