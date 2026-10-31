//! Disk volume for the storage server (SPEC §B6).
//!
//! The disk has three regions and no general-purpose filesystem:
//!
//! - two superblocks (CRC32 + generation); the valid copy with the higher generation wins;
//! - an append-only log of length-prefixed segments, each with a CRC32;
//! - a content-addressed extent area whose index is the extent headers themselves, so it
//!   can be rebuilt by scanning.
//!
//! Crash consistency: a log segment (or extent) is written and flushed *before* the
//! superblock moves. Recovery trusts only what the newest valid superblock names, then
//! checks each segment CRC and the hash chain of the log entries. A broken chain or a bad
//! CRC of committed data puts the volume into read-only safe mode (BS4). Bytes past the
//! committed length, including a segment flushed but not yet named by the superblock, are
//! ignored (BS5).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use aos_log::{Corruption, Entry, GENESIS};
use aos_types::Hash256;

pub mod wire;

pub const SECTOR: u64 = 512;
/// Superblock A and B, one sector each.
pub const SUPER_SLOTS: u64 = 2;
pub const LOG_START: u64 = SUPER_SLOTS * SECTOR;
/// 16 MiB of append-only log. The rest of the disk is the CAS area.
pub const LOG_BYTES: u64 = 16 * 1024 * 1024;
pub const CAS_START: u64 = LOG_START + LOG_BYTES;

const SB_MAGIC: &[u8; 8] = b"AOSBLKv1";
const SB_BODY: usize = 76;
const SB_CRC: usize = 76;
const EXTENT_MAGIC: u32 = u32::from_le_bytes(*b"SAC1");

/// IEEE CRC-32 (ISO-HDLC), the same polynomial as zlib.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Why a volume cannot be trusted. `as_u8` is the code on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    HashMismatch {
        seq: u64,
    },
    BrokenLink {
        seq: u64,
    },
    SeqMismatch {
        seq: u64,
    },
    Undecodable {
        seq: u64,
    },
    /// A committed segment's CRC does not match, and the bytes are not a hash-chain failure
    /// we can name more precisely.
    SegmentCrc {
        seq: u64,
    },
    /// The superblock's stored anchor does not match the chain we just verified.
    Anchor,
    /// `log_bytes` does not end on a segment boundary.
    Truncated,
}

impl Fault {
    pub fn as_u8(self) -> u8 {
        match self {
            Fault::HashMismatch { .. } => 1,
            Fault::BrokenLink { .. } => 2,
            Fault::SeqMismatch { .. } => 3,
            Fault::Undecodable { .. } => 4,
            Fault::SegmentCrc { .. } => 5,
            Fault::Anchor => 6,
            Fault::Truncated => 7,
        }
    }

    pub fn seq(self) -> u64 {
        match self {
            Fault::HashMismatch { seq }
            | Fault::BrokenLink { seq }
            | Fault::SeqMismatch { seq }
            | Fault::Undecodable { seq }
            | Fault::SegmentCrc { seq } => seq,
            Fault::Anchor | Fault::Truncated => 0,
        }
    }

    /// Hash-chain failures, as opposed to a structural CRC/framing failure.
    pub fn is_hash_chain(self) -> bool {
        matches!(self, Fault::HashMismatch { .. } | Fault::BrokenLink { .. } | Fault::SeqMismatch { .. })
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::HashMismatch { seq } => write!(f, "hash chain broken at seq {seq}: hash mismatch"),
            Fault::BrokenLink { seq } => write!(f, "hash chain broken at seq {seq}: broken link"),
            Fault::SeqMismatch { seq } => write!(f, "hash chain broken at seq {seq}: sequence mismatch"),
            Fault::Undecodable { seq } => write!(f, "log corrupt at seq {seq}: undecodable entry"),
            Fault::SegmentCrc { seq } => write!(f, "log corrupt at seq {seq}: segment CRC"),
            Fault::Anchor => write!(f, "hash chain broken: superblock anchor mismatch"),
            Fault::Truncated => write!(f, "log corrupt: committed length is not a segment boundary"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error<E> {
    Device(E),
    ReadOnly,
    /// The log segment is durable; the superblock was deliberately not updated.
    Halted,
    Corrupt(Fault),
    NoSpace,
    NotFound,
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Device(e) => write!(f, "device: {e:?}"),
            Error::ReadOnly => write!(f, "read-only safe mode"),
            Error::Halted => write!(f, "halted before superblock"),
            Error::Corrupt(fault) => write!(f, "{fault}"),
            Error::NoSpace => write!(f, "no space"),
            Error::NotFound => write!(f, "not found"),
        }
    }
}

/// A 512-byte-sector device. `read_sectors` / `write_sectors` transfer whole sectors;
/// `buf.len()` is `count * 512`.
pub trait BlockDevice {
    type Error: fmt::Debug;

    fn sector_count(&self) -> u64;
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error>;
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}

/// In-memory disk for the format tests and the host-side crash tests.
#[derive(Clone, Debug)]
pub struct MemDisk {
    data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemFault;

impl MemDisk {
    pub fn new(bytes: usize) -> MemDisk {
        MemDisk { data: alloc::vec![0; bytes] }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl BlockDevice for MemDisk {
    type Error = MemFault;

    fn sector_count(&self) -> u64 {
        self.data.len() as u64 / SECTOR
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), MemFault> {
        let start = (lba * SECTOR) as usize;
        let end = start + buf.len();
        buf.copy_from_slice(self.data.get(start..end).ok_or(MemFault)?);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), MemFault> {
        let start = (lba * SECTOR) as usize;
        let end = start + buf.len();
        let dst = self.data.get_mut(start..end).ok_or(MemFault)?;
        dst.copy_from_slice(buf);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), MemFault> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct Super {
    generation: u64,
    log_bytes: u64,
    entries: u64,
    anchor: Hash256,
    cas_bytes: u64,
    slot: usize,
}

fn encode_super(s: &Super) -> [u8; SECTOR as usize] {
    let mut raw = [0u8; SECTOR as usize];
    raw[..8].copy_from_slice(SB_MAGIC);
    raw[8..16].copy_from_slice(&s.generation.to_le_bytes());
    raw[16..24].copy_from_slice(&s.log_bytes.to_le_bytes());
    raw[24..32].copy_from_slice(&s.entries.to_le_bytes());
    raw[32..64].copy_from_slice(&s.anchor.0);
    raw[64..72].copy_from_slice(&s.cas_bytes.to_le_bytes());
    let crc = crc32(&raw[..SB_BODY]);
    raw[SB_CRC..SB_CRC + 4].copy_from_slice(&crc.to_le_bytes());
    raw
}

fn decode_super(raw: &[u8], slot: usize) -> Option<Super> {
    if raw.len() < SECTOR as usize || &raw[..8] != SB_MAGIC {
        return None;
    }
    let crc = u32::from_le_bytes(raw[SB_CRC..SB_CRC + 4].try_into().ok()?);
    if crc != crc32(&raw[..SB_BODY]) {
        return None;
    }
    let generation = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    let log_bytes = u64::from_le_bytes(raw[16..24].try_into().ok()?);
    let entries = u64::from_le_bytes(raw[24..32].try_into().ok()?);
    let mut anchor = [0u8; 32];
    anchor.copy_from_slice(&raw[32..64]);
    let cas_bytes = u64::from_le_bytes(raw[64..72].try_into().ok()?);
    if log_bytes > LOG_BYTES || generation == 0 {
        return None;
    }
    Some(Super { generation, log_bytes, entries, anchor: Hash256(anchor), cas_bytes, slot })
}

/// A mounted volume. `fault` is set when committed data does not verify; the volume then
/// rejects every mutation (read-only safe mode).
pub struct Volume<D: BlockDevice> {
    dev: D,
    superblock: Super,
    /// Committed entry bytes, filled from disk on open and extended on append.
    /// Recovery always re-reads the disk; this is the verified cache.
    payloads: Vec<Vec<u8>>,
    fault: Option<Fault>,
    /// Next append flushes the segment and returns [`Error::Halted`] without touching the
    /// superblock.
    halt_before_super: bool,
}

impl<D: BlockDevice> Volume<D> {
    pub fn open(mut dev: D) -> Result<Volume<D>, Error<D::Error>> {
        if dev.sector_count() * SECTOR < CAS_START + SECTOR {
            return Err(Error::NoSpace);
        }
        let superblock = read_super(&mut dev)?.unwrap_or(Super {
            generation: 0,
            log_bytes: 0,
            entries: 0,
            anchor: GENESIS,
            cas_bytes: 0,
            slot: 1,
        });
        let mut vol = Volume { dev, superblock, payloads: Vec::new(), fault: None, halt_before_super: false };
        if (vol.superblock.entries > 0 || vol.superblock.log_bytes > 0)
            && let Err(fault) = vol.verify_log()
        {
            vol.fault = Some(fault);
        }
        Ok(vol)
    }

    pub fn fault(&self) -> Option<Fault> {
        self.fault
    }

    pub fn read_only(&self) -> bool {
        self.fault.is_some()
    }

    pub fn anchor(&self) -> Hash256 {
        if self.fault.is_some() { GENESIS } else { self.superblock.anchor }
    }

    pub fn into_device(self) -> D {
        self.dev
    }

    pub fn sync(&mut self) -> Result<(), Error<D::Error>> {
        self.dev.flush().map_err(Error::Device)
    }

    /// BS5: the next successful segment write becomes durable, then append stops before
    /// the superblock is updated.
    pub fn arm_halt(&mut self) {
        self.halt_before_super = true;
    }

    pub fn cas_put(&mut self, hash: &Hash256, bytes: &[u8]) -> Result<(), Error<D::Error>> {
        self.ensure_writable()?;
        if bytes.len() > 1024 * 1024 {
            return Err(Error::NoSpace);
        }
        let mut extent = Vec::with_capacity(44 + bytes.len());
        extent.extend_from_slice(&EXTENT_MAGIC.to_le_bytes());
        extent.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        extent.extend_from_slice(&hash.0);
        extent.extend_from_slice(&crc32(bytes).to_le_bytes());
        extent.extend_from_slice(bytes);
        while extent.len() % 4 != 0 {
            extent.push(0);
        }
        let at = self.superblock.cas_bytes;
        let disk_end = self.dev.sector_count() * SECTOR;
        if CAS_START + at + extent.len() as u64 > disk_end {
            return Err(Error::NoSpace);
        }
        self.write_at(CAS_START + at, &extent)?;
        self.dev.flush().map_err(Error::Device)?;
        self.superblock.cas_bytes = at + extent.len() as u64;
        self.commit_super()
    }

    pub fn cas_get(&mut self, hash: &Hash256) -> Result<Vec<u8>, Error<D::Error>> {
        let mut at = 0u64;
        while at < self.superblock.cas_bytes {
            let mut hdr = [0u8; 44];
            self.read_at(CAS_START + at, &mut hdr)?;
            let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
            let len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as u64;
            if magic != EXTENT_MAGIC || at + 44 + len > self.superblock.cas_bytes {
                return Err(Error::Corrupt(Fault::Truncated));
            }
            let mut data = alloc::vec![0u8; len as usize];
            self.read_at(CAS_START + at + 44, &mut data)?;
            let stored = Hash256(hdr[8..40].try_into().unwrap());
            let crc = u32::from_le_bytes(hdr[40..44].try_into().unwrap());
            if crc != crc32(&data) {
                return Err(Error::Corrupt(Fault::SegmentCrc { seq: 0 }));
            }
            let step = (44 + len + 3) & !3;
            if stored == *hash {
                return Ok(data);
            }
            at += step;
        }
        Err(Error::NotFound)
    }

    fn ensure_writable(&self) -> Result<(), Error<D::Error>> {
        if self.fault.is_some() { Err(Error::ReadOnly) } else { Ok(()) }
    }

    fn verify_log(&mut self) -> Result<(), Fault> {
        let mut off = 0u64;
        let mut prev = GENESIS;
        let mut seq = 0u64;
        let committed = self.superblock.log_bytes;
        self.payloads.clear();
        while off < committed {
            let (payload, next, crc_ok) = self.read_segment(off, committed).map_err(|e| match e {
                Error::Corrupt(f) => f,
                _ => Fault::Truncated,
            })?;
            // A payload byte flip fails the segment CRC *and* the entry hash. The hash
            // chain is the result BS4 looks for, so it wins when both fail.
            let decoded = Entry::decode(&payload);
            if matches!(decoded, Err(Corruption::HashMismatch)) {
                return Err(Fault::HashMismatch { seq });
            }
            if !crc_ok {
                return Err(Fault::SegmentCrc { seq });
            }
            let entry = match decoded {
                Ok(e) => e,
                Err(Corruption::Undecodable(_)) => return Err(Fault::Undecodable { seq }),
                Err(Corruption::HashMismatch) => return Err(Fault::HashMismatch { seq }),
                Err(Corruption::SeqMismatch) => return Err(Fault::SeqMismatch { seq }),
                Err(Corruption::BrokenLink) => return Err(Fault::BrokenLink { seq }),
            };
            if entry.seq != seq {
                return Err(Fault::SeqMismatch { seq });
            }
            if entry.prev_hash != prev {
                return Err(Fault::BrokenLink { seq });
            }
            prev = entry.hash;
            self.payloads.push(payload);
            seq += 1;
            off = next;
        }
        if off != committed {
            return Err(Fault::Truncated);
        }
        if seq != self.superblock.entries || prev != self.superblock.anchor {
            return Err(Fault::Anchor);
        }
        Ok(())
    }

    /// Reads the segment at `off`. `crc_ok` is false when the stored CRC does not match;
    /// the payload is still returned so the caller can check the hash chain.
    fn read_segment(&mut self, off: u64, committed: u64) -> Result<(Vec<u8>, u64, bool), Error<D::Error>> {
        if off + 8 > committed {
            return Err(Error::Corrupt(Fault::Truncated));
        }
        let mut len_buf = [0u8; 4];
        self.read_at(LOG_START + off, &mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as u64;
        if len > 1024 * 1024 || off + 8 + len > committed {
            return Err(Error::Corrupt(Fault::Truncated));
        }
        let mut payload = alloc::vec![0u8; len as usize];
        self.read_at(LOG_START + off + 4, &mut payload)?;
        let mut crc_buf = [0u8; 4];
        self.read_at(LOG_START + off + 4 + len, &mut crc_buf)?;
        let stored = u32::from_le_bytes(crc_buf);
        let crc_ok = stored == crc32(&payload);
        let next = (off + 8 + len + 3) & !3;
        Ok((payload, next, crc_ok))
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), Error<D::Error>> {
        let mut done = 0;
        while done < buf.len() {
            let pos = off + done as u64;
            let lba = pos / SECTOR;
            let skip = (pos % SECTOR) as usize;
            let mut sector = [0u8; SECTOR as usize];
            self.dev.read_sectors(lba, &mut sector).map_err(Error::Device)?;
            let n = (SECTOR as usize - skip).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&sector[skip..skip + n]);
            done += n;
        }
        Ok(())
    }

    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), Error<D::Error>> {
        let mut done = 0;
        while done < buf.len() {
            let pos = off + done as u64;
            let lba = pos / SECTOR;
            let skip = (pos % SECTOR) as usize;
            let mut sector = [0u8; SECTOR as usize];
            let n = (SECTOR as usize - skip).min(buf.len() - done);
            if skip != 0 || n != SECTOR as usize {
                self.dev.read_sectors(lba, &mut sector).map_err(Error::Device)?;
            }
            sector[skip..skip + n].copy_from_slice(&buf[done..done + n]);
            self.dev.write_sectors(lba, &sector).map_err(Error::Device)?;
            done += n;
        }
        Ok(())
    }

    fn commit_super(&mut self) -> Result<(), Error<D::Error>> {
        self.superblock.generation = self.superblock.generation.saturating_add(1).max(1);
        self.superblock.slot ^= 1;
        let raw = encode_super(&self.superblock);
        self.dev.write_sectors(self.superblock.slot as u64, &raw).map_err(Error::Device)?;
        self.dev.flush().map_err(Error::Device)?;
        Ok(())
    }
}

impl<D: BlockDevice> aos_log::LogStorage for Volume<D> {
    type Error = Error<D::Error>;

    fn append(&mut self, entry: &[u8]) -> Result<(), Self::Error> {
        self.ensure_writable()?;
        let decoded =
            Entry::decode(entry).map_err(|_| Error::Corrupt(Fault::Undecodable { seq: self.superblock.entries }))?;
        if decoded.seq != self.superblock.entries || decoded.prev_hash != self.superblock.anchor {
            return Err(Error::Corrupt(Fault::BrokenLink { seq: self.superblock.entries }));
        }
        let mut segment = Vec::with_capacity(entry.len() + 8);
        segment.extend_from_slice(&(entry.len() as u32).to_le_bytes());
        segment.extend_from_slice(entry);
        segment.extend_from_slice(&crc32(entry).to_le_bytes());
        while segment.len() % 4 != 0 {
            segment.push(0);
        }
        let at = self.superblock.log_bytes;
        if at + segment.len() as u64 > LOG_BYTES {
            return Err(Error::NoSpace);
        }
        self.write_at(LOG_START + at, &segment)?;
        self.dev.flush().map_err(Error::Device)?;
        if self.halt_before_super {
            self.halt_before_super = false;
            return Err(Error::Halted);
        }
        self.payloads.push(entry.to_vec());
        self.superblock.log_bytes = at + segment.len() as u64;
        self.superblock.entries += 1;
        self.superblock.anchor = decoded.hash;
        self.commit_super()
    }

    fn len(&self) -> u64 {
        if self.fault.is_some() { 0 } else { self.superblock.entries }
    }

    fn read(&self, seq: u64) -> Result<Vec<u8>, Self::Error> {
        if self.fault.is_some() {
            return Err(Error::ReadOnly);
        }
        self.payloads.get(seq as usize).cloned().ok_or(Error::NotFound)
    }
}

fn read_super<D: BlockDevice>(dev: &mut D) -> Result<Option<Super>, Error<D::Error>> {
    let mut best: Option<Super> = None;
    for slot in 0..SUPER_SLOTS as usize {
        let mut raw = [0u8; SECTOR as usize];
        dev.read_sectors(slot as u64, &mut raw).map_err(Error::Device)?;
        if let Some(s) = decode_super(&raw, slot)
            && best.as_ref().is_none_or(|b| s.generation > b.generation)
        {
            best = Some(s);
        }
    }
    Ok(best)
}

/// Flips one letter inside the first committed log payload and leaves the segment CRC
/// stale, so recovery has to notice the hash chain (BS4). Returns the disk offset flipped.
pub fn tamper_log_payload(image: &mut [u8]) -> Result<usize, &'static str> {
    let sector = |slot: usize| {
        let start = slot * SECTOR as usize;
        image.get(start..start + SECTOR as usize).ok_or("short image")
    };
    let a = decode_super(sector(0)?, 0);
    let b = decode_super(sector(1)?, 1);
    let sb = match (a, b) {
        (Some(a), Some(b)) if b.generation > a.generation => b,
        (Some(a), Some(_)) => a,
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return Err("no superblock"),
    };
    if sb.log_bytes < 8 {
        return Err("empty log");
    }
    let base = LOG_START as usize;
    let len = u32::from_le_bytes(image[base..base + 4].try_into().unwrap()) as usize;
    if len < 8 || base + 4 + len > image.len() {
        return Err("bad segment");
    }
    let payload = &mut image[base + 4..base + 4 + len];
    // Flip a byte inside a CBOR text *value* (not a map key). The encoding stays
    // canonical, so recovery reaches the entry hash and reports a broken chain.
    let mut i = 0;
    let mut flip_at = None;
    scan_cbor(payload, &mut i, &mut flip_at).map_err(|_| "undecodable payload")?;
    let at = flip_at.ok_or("no text value")?;
    payload[at] ^= 0x01;
    Ok(base + 4 + at)
}

/// Walks one deterministic-CBOR value. Records the last byte of the last text value.
fn scan_cbor(data: &[u8], i: &mut usize, flip_at: &mut Option<usize>) -> Result<(), ()> {
    let b = *data.get(*i).ok_or(())?;
    *i += 1;
    let major = b >> 5;
    let info = b & 0x1f;
    let add = |data: &[u8], i: &mut usize, info: u8| -> Result<u64, ()> {
        Ok(match info {
            0..=23 => info as u64,
            24 => {
                let n = *data.get(*i).ok_or(())? as u64;
                *i += 1;
                n
            }
            25 => {
                let n = u16::from_be_bytes(data.get(*i..*i + 2).ok_or(())?.try_into().map_err(|_| ())?);
                *i += 2;
                n as u64
            }
            26 => {
                let n = u32::from_be_bytes(data.get(*i..*i + 4).ok_or(())?.try_into().map_err(|_| ())?);
                *i += 4;
                n as u64
            }
            27 => {
                let n = u64::from_be_bytes(data.get(*i..*i + 8).ok_or(())?.try_into().map_err(|_| ())?);
                *i += 8;
                n
            }
            _ => return Err(()),
        })
    };
    match major {
        0 | 1 | 7 => {
            add(data, i, info)?;
        }
        2 | 3 => {
            let n = add(data, i, info)? as usize;
            if major == 3 && n > 0 {
                *flip_at = Some(*i + n - 1);
            }
            *i += n;
        }
        4 => {
            let n = add(data, i, info)?;
            for _ in 0..n {
                scan_cbor(data, i, flip_at)?;
            }
        }
        5 => {
            let n = add(data, i, info)?;
            for _ in 0..n {
                let saved = *flip_at;
                scan_cbor(data, i, flip_at)?;
                *flip_at = saved;
                scan_cbor(data, i, flip_at)?;
            }
        }
        6 => {
            add(data, i, info)?;
            scan_cbor(data, i, flip_at)?;
        }
        _ => return Err(()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_log::{Log, LogStorage, MemStorage};
    use aos_types::cbor::Cbor;

    fn disk() -> MemDisk {
        MemDisk::new((CAS_START + 64 * 1024) as usize)
    }

    fn entry_bytes(n: u64) -> Vec<Vec<u8>> {
        let mut log = Log::open(MemStorage::new(), None, |_| Ok::<(), ()>(())).unwrap();
        let mut out = Vec::new();
        for i in 0..n {
            let e = log.append(Cbor::Array(alloc::vec![Cbor::Unsigned(i), Cbor::text("record")])).unwrap();
            out.push(e.encode());
        }
        out
    }

    #[test]
    fn append_is_durable_across_reopen() {
        let bytes = entry_bytes(3);
        let mut vol = Volume::open(disk()).unwrap();
        for e in &bytes {
            LogStorage::append(&mut vol, e).unwrap();
        }
        assert_eq!(vol.len(), 3);
        assert_eq!(LogStorage::read(&vol, 1).unwrap(), bytes[1]);
        let again = Volume::open(vol.into_device()).unwrap();
        assert_eq!(again.fault(), None);
        assert_eq!(again.len(), 3);
        assert_eq!(LogStorage::read(&again, 2).unwrap(), bytes[2]);
        let log = Log::open(again, None, |_| Ok::<(), ()>(())).unwrap();
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn halt_before_superblock_drops_the_uncommitted_entry() {
        let bytes = entry_bytes(2);
        let mut vol = Volume::open(disk()).unwrap();
        LogStorage::append(&mut vol, &bytes[0]).unwrap();
        vol.arm_halt();
        assert_eq!(LogStorage::append(&mut vol, &bytes[1]), Err(Error::Halted));
        let again = Volume::open(vol.into_device()).unwrap();
        assert_eq!(again.fault(), None, "uncommitted tail must not look like corruption");
        assert_eq!(again.len(), 1);
        assert_eq!(LogStorage::read(&again, 0).unwrap(), bytes[0]);
        assert!(LogStorage::read(&again, 1).is_err());
    }

    #[test]
    fn a_torn_superblock_falls_back_to_the_previous_generation() {
        let bytes = entry_bytes(2);
        let mut vol = Volume::open(disk()).unwrap();
        LogStorage::append(&mut vol, &bytes[0]).unwrap();
        LogStorage::append(&mut vol, &bytes[1]).unwrap();
        let slot = vol.superblock.slot;
        let mut image = vol.into_device();
        image.as_mut_slice()[slot * SECTOR as usize] ^= 0xff;
        let again = Volume::open(image).unwrap();
        assert_eq!(again.fault(), None);
        assert_eq!(again.len(), 1, "generation 2 is discarded with its torn superblock");
        assert_eq!(LogStorage::read(&again, 0).unwrap(), bytes[0]);
    }

    #[test]
    fn tampering_a_payload_byte_breaks_the_hash_chain_and_is_read_only() {
        let bytes = entry_bytes(2);
        let mut vol = Volume::open(disk()).unwrap();
        for e in &bytes {
            LogStorage::append(&mut vol, e).unwrap();
        }
        let mut image = vol.into_device();
        let flipped = tamper_log_payload(image.as_mut_slice()).unwrap();
        assert!(flipped >= LOG_START as usize);
        let mut again = Volume::open(image).unwrap();
        let fault = again.fault().expect("tamper detected");
        assert!(fault.is_hash_chain(), "{fault}");
        assert!(matches!(fault, Fault::HashMismatch { seq: 0 }));
        assert_eq!(LogStorage::append(&mut again, &bytes[0]), Err(Error::ReadOnly));
        assert_eq!(again.len(), 0);
    }

    #[test]
    fn cas_round_trip_and_ignored_extent_after_a_missed_superblock() {
        let hash = Hash256::digest(b"blob");
        let mut vol = Volume::open(disk()).unwrap();
        vol.cas_put(&hash, b"blob-bytes").unwrap();
        assert_eq!(vol.cas_get(&hash).unwrap(), b"blob-bytes");
        let dev = vol.into_device();
        let mut again = Volume::open(dev).unwrap();
        assert_eq!(again.cas_get(&hash).unwrap(), b"blob-bytes");
    }

    #[test]
    fn wire_frames_round_trip() {
        use crate::wire::{self, Frame, Stat};
        let stat = Stat { read_only: true, fault: 1, fault_seq: 4, entries: 9, anchor: [7; 32] };
        assert_eq!(Stat::decode(&stat.encode()).unwrap(), stat);
        let frame = Frame::request(wire::OP_APPEND, 3, alloc::vec![1, 2, 3, 4]);
        let mut buf = frame.encode();
        buf.extend_from_slice(&[0xff]);
        let got = wire::decode(&mut buf).unwrap().unwrap();
        assert_eq!(got, frame);
        assert_eq!(buf, alloc::vec![0xff]);
    }
}
