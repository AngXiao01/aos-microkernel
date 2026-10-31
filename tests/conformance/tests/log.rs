//! §16.1 日志：哈希链完整；篡改任何一条都能被检测到。

use aos_branch::{BranchId, Store};
use aos_conformance::{TestEnv, new_store, reopen, set};
use aos_log::{Entry, LogError, OpenError};
use aos_types::Actor;

fn busy_store() -> aos_conformance::MemStore {
    let mut s = new_store();
    let ids: Vec<_> = (0..3).map(|_| s.new_id().unwrap()).collect();
    for (i, id) in ids.iter().enumerate() {
        set(&mut s, BranchId::Main, *id, i as i64);
    }
    let fork = s.fork(Actor::User).unwrap();
    set(&mut s, fork, ids[0], 100);
    let BranchId::Fork(f) = fork else { unreachable!() };
    s.submit(f, Actor::System).unwrap();
    s.commit(f, Actor::User).unwrap();
    let tx = set(&mut s, BranchId::Main, ids[1], 7);
    s.revert(BranchId::Main, tx, Actor::User).unwrap();
    s
}

#[test]
fn store_log_chain_is_intact_and_replays() {
    let s = busy_store();
    assert_eq!(s.log().len(), 9);
    let mut prev = aos_log::GENESIS;
    for seq in 0..s.log().len() {
        let e = s.log().read(seq).unwrap();
        assert_eq!(e.prev_hash, prev);
        prev = e.hash;
    }
    assert_eq!(prev, s.anchor().head);
    reopen(&s);
}

#[test]
fn every_byte_of_every_entry_is_tamper_evident() {
    let s = busy_store();
    let storage = s.log().storage().clone();
    for seq in 0..storage.clone().entries_mut().len() {
        let len = storage.clone().entries_mut()[seq].len();
        for i in 0..len {
            let mut tampered = storage.clone();
            tampered.entries_mut()[seq][i] ^= 0x20;
            match Store::open(tampered, TestEnv::new(1), None) {
                Err(OpenError::Log(LogError::Corrupt { seq: at, .. })) => assert_eq!(at, seq as u64),
                Err(other) => panic!("entry {seq} byte {i}: unexpected error {other:?}"),
                Ok(_) => panic!("entry {seq} byte {i}: tampering went unnoticed"),
            }
        }
    }
}

#[test]
fn a_rehashed_forgery_breaks_the_chain_and_a_truncation_breaks_the_anchor() {
    let s = busy_store();
    let mut forged = s.log().storage().clone();
    let original = Entry::decode(&forged.entries_mut()[4]).unwrap();
    let mut record = original.record.clone();
    if let aos_types::Cbor::Map(m) = &mut record {
        m.insert(aos_types::Cbor::text("timestamp"), aos_types::Cbor::Unsigned(1));
    }
    // Re-encode a self-consistent entry 4 by appending it to a copy of entries 0..4.
    let mut prefix = aos_log::MemStorage::new();
    for e in &forged.entries_mut()[..4] {
        aos_log::LogStorage::append(&mut prefix, e).unwrap();
    }
    let mut log = aos_log::Log::open(prefix, None, |_| Ok::<(), ()>(())).unwrap();
    let forged_entry = log.append(record).unwrap();
    forged.entries_mut()[4] = forged_entry.encode();
    assert!(matches!(
        Store::open(forged, TestEnv::new(1), None),
        Err(OpenError::Log(LogError::Corrupt { seq: 5, corruption: aos_log::Corruption::BrokenLink }))
    ));

    let mut truncated = s.log().storage().clone();
    truncated.entries_mut().pop();
    assert!(Store::open(truncated.clone(), TestEnv::new(1), None).is_ok());
    assert!(matches!(
        Store::open(truncated, TestEnv::new(1), Some(s.anchor())),
        Err(OpenError::Log(LogError::AnchorMismatch))
    ));
}

#[test]
fn a_valid_entry_with_an_impossible_record_is_rejected_on_replay() {
    // Entries are hash-valid, but the record deletes an object that does not exist.
    let mut s = new_store();
    let id = s.new_id().unwrap();
    set(&mut s, BranchId::Main, id, 1);
    let mut storage = s.log().storage().clone();
    let entry = Entry::decode(&storage.entries_mut()[0]).unwrap();
    let mut record: aos_branch::Record = aos_types::FromCbor::from_cbor(&entry.record).unwrap();
    if let aos_branch::Op::Write { writes, .. } = &mut record.op {
        writes[0].prev_version = Some(1);
        writes[0].change = aos_branch::Change::Delete;
    }
    let mut log = aos_log::Log::open(aos_log::MemStorage::new(), None, |_| Ok::<(), ()>(())).unwrap();
    log.append(aos_types::ToCbor::to_cbor(&record)).unwrap();
    storage.entries_mut()[0] = log.read(0).unwrap().encode();
    assert!(matches!(Store::open(storage, TestEnv::new(1), None), Err(OpenError::Visit { seq: 0, .. })));
}
