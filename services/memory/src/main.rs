//! The memory server (§B4): owns a subset of the Untyped memory and hands out frames.
//!
//! x0: the first slot holding its Untyped capabilities; x1: how many. Its service endpoint
//! is in slot 1 and its own CNode capability in slot 2.

#![no_std]
#![no_main]

use aos_rt::abi::{Error, MAX_MSG_CAPS, MsgInfo, object};
use aos_rt::cap::{delete, retype};
use aos_rt::proto::memory::{ALLOC_FRAMES, UNKNOWN};
use aos_rt::{ipc_buffer, recv, reply};

aos_rt::entry!(main);

const SERVICE: u64 = 1;
const CNODE: u64 = 2;
/// Where frames are made before they are transferred.
const SCRATCH: u64 = 200;

fn main(first_untyped: u64, count: u64) -> u64 {
    let end = first_untyped + count;
    let mut current = first_untyped;
    loop {
        let r = recv(SERVICE, 0);
        if !r.is_ok() {
            continue;
        }
        if r.info.label() != ALLOC_FRAMES {
            reply(MsgInfo::new(UNKNOWN, 0), [0; 4]);
            continue;
        }
        let wanted = r.words[0].clamp(1, MAX_MSG_CAPS as u64);
        let mut made = 0;
        while made < wanted && current < end {
            match retype(current, object::FRAME, SCRATCH + made, 1) {
                Ok(()) => made += 1,
                Err(Error::NoMemory) => current += 1,
                Err(_) => break,
            }
        }
        for i in 0..made as usize {
            ipc_buffer().caps[i] = SCRATCH + i as u64;
        }
        reply(MsgInfo::new(ALLOC_FRAMES, 1).with_caps(made as usize), [made, 0, 0, 0]);
        // The client's copies are children of these; they survive the deletion.
        for i in 0..made {
            let _ = delete(CNODE, SCRATCH + i);
        }
    }
}
