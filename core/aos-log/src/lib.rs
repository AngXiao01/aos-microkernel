//! Append-only, hash-chained log (SPEC §7.1), the single source of truth.
//!
//! Each entry carries a sequence number, the hash of the previous entry and an opaque
//! record (deterministic CBOR; its schema belongs to the layer above). The entry hash is
//! `SHA-256(canonical_cbor({seq, prev_hash, record}))`. Opening a log verifies the whole
//! chain; an [`Anchor`] kept elsewhere (superblock, signed checkpoint) also detects a
//! truncated tail, which the chain alone cannot.
//!
//! Storage is behind [`LogStorage`]; [`MemStorage`] is the in-memory backend.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use aos_types::cbor::{self, Cbor};
use aos_types::{FormatError, Hash256};

/// `prev_hash` of the first entry.
pub const GENESIS: Hash256 = Hash256([0; 32]);

/// Persistent backend. Entries are opaque byte strings addressed by sequence number.
pub trait LogStorage {
    type Error: fmt::Debug;

    /// Appends one encoded entry; it must be durable when this returns `Ok`.
    fn append(&mut self, entry: &[u8]) -> Result<(), Self::Error>;

    /// Number of stored entries.
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read(&self, seq: u64) -> Result<Vec<u8>, Self::Error>;
}

/// In-memory storage. `Clone` gives tests an independent copy to reopen or tamper with.
#[derive(Clone, Debug, Default)]
pub struct MemStorage {
    entries: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfRange;

impl MemStorage {
    pub fn new() -> MemStorage {
        MemStorage::default()
    }

    /// Raw access for tamper tests.
    pub fn entries_mut(&mut self) -> &mut Vec<Vec<u8>> {
        &mut self.entries
    }
}

impl LogStorage for MemStorage {
    type Error = OutOfRange;

    fn append(&mut self, entry: &[u8]) -> Result<(), OutOfRange> {
        self.entries.push(entry.to_vec());
        Ok(())
    }

    fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    fn read(&self, seq: u64) -> Result<Vec<u8>, OutOfRange> {
        usize::try_from(seq).ok().and_then(|i| self.entries.get(i)).cloned().ok_or(OutOfRange)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub prev_hash: Hash256,
    pub record: Cbor,
    pub hash: Hash256,
}

/// The canonical encoding of the entry map, written directly so that a large record is
/// encoded once and never cloned. Keys in deterministic order: `seq`, `hash`, `record`,
/// `prev_hash` (the hashed form omits `hash`).
fn frame(seq: u64, prev_hash: &Hash256, record: &[u8], hash: Option<&Hash256>) -> Vec<u8> {
    let mut out = Vec::with_capacity(record.len() + 96);
    out.push(if hash.is_some() { 0xa4 } else { 0xa3 });
    let mut put = |c: &Cbor| cbor::encode_into(c, &mut out);
    put(&Cbor::text("seq"));
    put(&Cbor::Unsigned(seq));
    if let Some(h) = hash {
        put(&Cbor::text("hash"));
        put(&Cbor::Bytes(h.0.to_vec()));
    }
    put(&Cbor::text("record"));
    out.extend_from_slice(record);
    cbor::encode_into(&Cbor::text("prev_hash"), &mut out);
    cbor::encode_into(&Cbor::Bytes(prev_hash.0.to_vec()), &mut out);
    out
}

impl Entry {
    /// The entry and its stored encoding.
    fn build(seq: u64, prev_hash: Hash256, record: Cbor) -> (Entry, Vec<u8>) {
        let record_bytes = cbor::encode(&record);
        let hash = Hash256::digest(&frame(seq, &prev_hash, &record_bytes, None));
        let bytes = frame(seq, &prev_hash, &record_bytes, Some(&hash));
        (Entry { seq, prev_hash, record, hash }, bytes)
    }

    pub fn encode(&self) -> Vec<u8> {
        frame(self.seq, &self.prev_hash, &cbor::encode(&self.record), Some(&self.hash))
    }

    /// Strict decoding plus a check that `hash` matches the content.
    pub fn decode(bytes: &[u8]) -> Result<Entry, Corruption> {
        let value = cbor::decode(bytes).map_err(|e| Corruption::Undecodable(FormatError::Cbor(e)))?;
        let Cbor::Map(map) = value else {
            return Err(Corruption::Undecodable(FormatError::WrongType("log entry")));
        };
        if map.len() != 4 {
            return Err(Corruption::Undecodable(FormatError::InvalidValue("log entry keys")));
        }
        let field = |k: &'static str| map.get_str(k).ok_or(Corruption::Undecodable(FormatError::MissingKey(k)));
        let hash = |k: &'static str| -> Result<Hash256, Corruption> {
            let b = field(k)?.as_bytes().ok_or(Corruption::Undecodable(FormatError::WrongType(k)))?;
            Ok(Hash256(b.try_into().map_err(|_| Corruption::Undecodable(FormatError::InvalidValue(k)))?))
        };
        let seq = field("seq")?.as_u64().ok_or(Corruption::Undecodable(FormatError::WrongType("seq")))?;
        let prev_hash = hash("prev_hash")?;
        let stored = hash("hash")?;
        let record = field("record")?;
        if Hash256::digest(&frame(seq, &prev_hash, &cbor::encode(record), None)) != stored {
            return Err(Corruption::HashMismatch);
        }
        Ok(Entry { seq, prev_hash, record: record.clone(), hash: stored })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Corruption {
    Undecodable(FormatError),
    HashMismatch,
    /// The entry's `seq` is not its position in the log.
    SeqMismatch,
    /// `prev_hash` does not match the previous entry.
    BrokenLink,
}

/// Where the log ended when it was last known good.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub len: u64,
    pub head: Hash256,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LogError<E> {
    Storage(E),
    Corrupt {
        seq: u64,
        corruption: Corruption,
    },
    /// The log does not end where the anchor says (truncated, or a different log).
    AnchorMismatch,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpenError<E, V> {
    Log(LogError<E>),
    /// The visitor rejected entry `seq`.
    Visit {
        seq: u64,
        error: V,
    },
}

pub struct Log<S> {
    storage: S,
    len: u64,
    head: Hash256,
}

impl<S: LogStorage> Log<S> {
    /// Verifies every entry and the chain, calling `visit` on each entry in order (replay).
    pub fn open<V>(
        storage: S,
        anchor: Option<Anchor>,
        mut visit: impl FnMut(&Entry) -> Result<(), V>,
    ) -> Result<Log<S>, OpenError<S::Error, V>> {
        let mut head = GENESIS;
        let len = storage.len();
        for seq in 0..len {
            let bytes = storage.read(seq).map_err(|e| OpenError::Log(LogError::Storage(e)))?;
            let corrupt = |corruption| OpenError::Log(LogError::Corrupt { seq, corruption });
            let entry = Entry::decode(&bytes).map_err(corrupt)?;
            if entry.seq != seq {
                return Err(corrupt(Corruption::SeqMismatch));
            }
            if entry.prev_hash != head {
                return Err(corrupt(Corruption::BrokenLink));
            }
            visit(&entry).map_err(|error| OpenError::Visit { seq, error })?;
            head = entry.hash;
        }
        let log = Log { storage, len, head };
        if anchor.is_some_and(|a| a != log.anchor()) {
            return Err(OpenError::Log(LogError::AnchorMismatch));
        }
        Ok(log)
    }

    pub fn append(&mut self, record: Cbor) -> Result<Entry, LogError<S::Error>> {
        let (entry, bytes) = Entry::build(self.len, self.head, record);
        self.storage.append(&bytes).map_err(LogError::Storage)?;
        self.len += 1;
        self.head = entry.hash;
        Ok(entry)
    }

    /// Reads one entry and checks its own hash. Chain links are checked by `open`.
    pub fn read(&self, seq: u64) -> Result<Entry, LogError<S::Error>> {
        let bytes = self.storage.read(seq).map_err(LogError::Storage)?;
        let entry = Entry::decode(&bytes).map_err(|corruption| LogError::Corrupt { seq, corruption })?;
        if entry.seq != seq {
            return Err(LogError::Corrupt { seq, corruption: Corruption::SeqMismatch });
        }
        Ok(entry)
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn anchor(&self) -> Anchor {
        Anchor { len: self.len, head: self.head }
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(s: MemStorage, anchor: Option<Anchor>) -> Result<Log<MemStorage>, OpenError<OutOfRange, ()>> {
        Log::open(s, anchor, |_| Ok(()))
    }

    fn sample_log(n: u64) -> Log<MemStorage> {
        let mut log = open(MemStorage::new(), None).unwrap();
        for i in 0..n {
            log.append(Cbor::Array(alloc::vec![Cbor::Unsigned(i), Cbor::text("record")])).unwrap();
        }
        log
    }

    #[test]
    fn chain_verifies_and_replays_in_order() {
        let log = sample_log(5);
        let mut seen = Vec::new();
        let reopened = Log::open(log.storage().clone(), Some(log.anchor()), |e| {
            seen.push(e.seq);
            Ok::<(), ()>(())
        })
        .unwrap();
        assert_eq!(seen, [0, 1, 2, 3, 4]);
        assert_eq!(reopened.anchor(), log.anchor());
        assert_eq!(log.read(3).unwrap().prev_hash, log.read(2).unwrap().hash);
        assert_eq!(log.read(0).unwrap().prev_hash, GENESIS);
    }

    #[test]
    fn every_single_byte_flip_is_detected() {
        let log = sample_log(4);
        for seq in 0..4usize {
            let len = log.storage().entries[seq].len();
            for i in 0..len {
                let mut s = log.storage().clone();
                s.entries_mut()[seq][i] ^= 0x01;
                let err = open(s, None).err().unwrap_or_else(|| panic!("flip at entry {seq} byte {i} went unnoticed"));
                assert!(matches!(err, OpenError::Log(LogError::Corrupt { seq: s, .. }) if s == seq as u64));
            }
        }
    }

    #[test]
    fn removal_reordering_and_rewriting_are_detected() {
        let log = sample_log(4);

        let mut s = log.storage().clone();
        s.entries_mut().remove(1);
        assert!(matches!(
            open(s, None),
            Err(OpenError::Log(LogError::Corrupt { seq: 1, corruption: Corruption::SeqMismatch }))
        ));

        let mut s = log.storage().clone();
        s.entries_mut().swap(1, 2);
        assert!(matches!(open(s, None), Err(OpenError::Log(LogError::Corrupt { seq: 1, .. }))));

        // A rewritten entry with a valid hash of its own breaks the next link.
        let mut s = log.storage().clone();
        let original = Entry::decode(&s.entries_mut()[1]).unwrap();
        s.entries_mut()[1] = Entry::build(1, original.prev_hash, Cbor::text("forged")).1;
        assert!(matches!(
            open(s, None),
            Err(OpenError::Log(LogError::Corrupt { seq: 2, corruption: Corruption::BrokenLink }))
        ));
    }

    #[test]
    fn anchor_detects_a_truncated_tail() {
        let log = sample_log(4);
        let anchor = log.anchor();
        let mut s = log.storage().clone();
        s.entries_mut().pop();
        assert!(open(s.clone(), None).is_ok(), "without an anchor a shorter prefix is a valid log");
        assert!(matches!(open(s, Some(anchor)), Err(OpenError::Log(LogError::AnchorMismatch))));
    }

    #[test]
    fn visitor_errors_stop_replay() {
        let log = sample_log(3);
        let r = Log::open(log.storage().clone(), None, |e| if e.seq == 1 { Err("bad record") } else { Ok(()) });
        assert!(matches!(r, Err(OpenError::Visit { seq: 1, error: "bad record" })));
    }
}
