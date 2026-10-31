//! Short byte chunks inside an IPC message.
//!
//! Word 0 is the length. The bytes start at word 1, so a chunk fits in the 64-word message
//! with room to spare ([`aos_abi::proto::hostlink::CHUNK`]).

use aos_abi::MsgInfo;

use crate::proto::hostlink::CHUNK;
use crate::{Reply, call, ipc_buffer, reply};

fn pack(bytes: &[u8]) -> [u64; 4] {
    let n = bytes.len().min(CHUNK);
    let mut words = [0u64; 64];
    words[0] = n as u64;
    // SAFETY: `words` is 512 bytes and `n + 8` stays inside it (`CHUNK` is 496).
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), words.as_mut_ptr().add(1) as *mut u8, n) };
    ipc_buffer().msg = words;
    [words[0], words[1], words[2], words[3]]
}

/// Copies a received chunk into `out`. `words` are the first four message words (registers).
pub fn unpack(words: [u64; 4], out: &mut [u8]) -> usize {
    let mut all = ipc_buffer().msg;
    all[..4].copy_from_slice(&words);
    let n = (all[0] as usize).min(CHUNK).min(out.len());
    // SAFETY: `all` is 512 bytes; `n` bytes starting at word 1 are in range.
    unsafe { core::ptr::copy_nonoverlapping(all.as_ptr().add(1) as *const u8, out.as_mut_ptr(), n) };
    n
}

pub fn call_chunk(endpoint: u64, label: u64, bytes: &[u8]) -> Reply {
    let words = pack(bytes);
    call(endpoint, MsgInfo::new(label, 64), words, 0)
}

pub fn reply_chunk(label: u64, bytes: &[u8]) -> Reply {
    let words = pack(bytes);
    reply(MsgInfo::new(label, 64), words)
}
