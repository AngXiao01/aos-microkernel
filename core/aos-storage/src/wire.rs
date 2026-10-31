//! Byte protocol between the host IPC adapter and the storage server (§B10).
//!
//! One frame is `magic, op, status, id, len, body`. The body is at most [`MAX_BODY`] bytes.
//! Both sides run this codec; the guest speaks it over virtio-console, the host over the
//! socket QEMU attaches to that console.

extern crate alloc;

use alloc::vec::Vec;

pub const MAGIC: u32 = u32::from_le_bytes(*b"AOSS");
pub const HEADER: usize = 16;
pub const MAX_BODY: usize = 64 * 1024;

pub const OP_HELLO: u16 = 1;
pub const OP_STAT: u16 = 2;
pub const OP_APPEND: u16 = 3;
pub const OP_READ: u16 = 4;
pub const OP_LEN: u16 = 5;
pub const OP_SHUTDOWN: u16 = 6;
/// The next [`OP_APPEND`] flushes the log segment and then stops before the superblock
/// update, so a power cut leaves that append uncommitted (BS5).
pub const OP_ARM_HALT: u16 = 7;
pub const OP_CAS_PUT: u16 = 8;
pub const OP_CAS_GET: u16 = 9;

pub const ST_OK: u16 = 0;
pub const ST_READ_ONLY: u16 = 1;
pub const ST_NOT_FOUND: u16 = 2;
pub const ST_CORRUPT: u16 = 3;
pub const ST_WILL_HALT: u16 = 4;
pub const ST_BAD: u16 = 5;
pub const ST_NO_SPACE: u16 = 6;

/// `STAT` / `HELLO` body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    pub read_only: bool,
    /// 0 when the volume is healthy. Otherwise a [`crate::Fault`] discriminant.
    pub fault: u8,
    pub fault_seq: u64,
    pub entries: u64,
    pub anchor: [u8; 32],
}

impl Stat {
    pub const LEN: usize = 1 + 1 + 6 + 8 + 8 + 32;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.push(u8::from(self.read_only));
        out.push(self.fault);
        out.extend_from_slice(&[0; 6]);
        out.extend_from_slice(&self.fault_seq.to_le_bytes());
        out.extend_from_slice(&self.entries.to_le_bytes());
        out.extend_from_slice(&self.anchor);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Stat> {
        if bytes.len() < Self::LEN {
            return None;
        }
        let fault_seq = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let entries = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&bytes[24..56]);
        Some(Stat { read_only: bytes[0] != 0, fault: bytes[1], fault_seq, entries, anchor })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub op: u16,
    pub status: u16,
    pub id: u32,
    pub body: Vec<u8>,
}

impl Frame {
    pub fn request(op: u16, id: u32, body: Vec<u8>) -> Frame {
        Frame { op, status: ST_OK, id, body }
    }

    pub fn response(op: u16, status: u16, id: u32, body: Vec<u8>) -> Frame {
        Frame { op, status, id, body }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.body.len());
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&self.op.to_le_bytes());
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Short,
    BadMagic,
    TooLarge,
}

/// Decodes one frame from the front of `buf`, removing it. `Ok(None)` means it needs more bytes.
pub fn decode(buf: &mut Vec<u8>) -> Result<Option<Frame>, DecodeError> {
    if buf.len() < HEADER {
        return Ok(None);
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let op = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    let status = u16::from_le_bytes(buf[6..8].try_into().unwrap());
    let id = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let len = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
    if len > MAX_BODY {
        return Err(DecodeError::TooLarge);
    }
    if buf.len() < HEADER + len {
        return Ok(None);
    }
    let body = buf[HEADER..HEADER + len].to_vec();
    buf.drain(..HEADER + len);
    Ok(Some(Frame { op, status, id, body }))
}
