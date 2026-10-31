//! Kernel object methods (`aos_abi::method`), as `CALL` on the object's capability.

use aos_abi::{Error, MsgInfo, method};

use crate::call;

/// Calls `method` on the object in `slot`; the result words on success.
pub fn invoke(slot: u64, method: u64, args: [u64; 4]) -> Result<[u64; 4], Error> {
    let r = call(slot, MsgInfo::new(method, 4), args, 0);
    match r.error() {
        Some(Error::Ok) => Ok(r.words),
        Some(e) => Err(e),
        None => Err(Error::InvalidArgument),
    }
}

pub fn retype(untyped: u64, kind: u64, dest: u64, count: u64) -> Result<(), Error> {
    invoke(untyped, method::RETYPE, [kind, dest, count, 0]).map(|_| ())
}

/// Copies the caller's `src` into `cnode[dest]` with `rights`.
pub fn copy(cnode: u64, src: u64, dest: u64, rights: u64) -> Result<(), Error> {
    invoke(cnode, method::COPY, [src, dest, rights, 0]).map(|_| ())
}

pub fn mint(cnode: u64, src: u64, dest: u64, rights: u64, badge: u64) -> Result<(), Error> {
    invoke(cnode, method::MINT, [src, dest, rights, badge]).map(|_| ())
}

/// Moves the caller's `src` into `cnode[dest]`.
pub fn move_cap(cnode: u64, src: u64, dest: u64) -> Result<(), Error> {
    invoke(cnode, method::MOVE, [src, dest, 0, 0]).map(|_| ())
}

pub fn delete(cnode: u64, index: u64) -> Result<(), Error> {
    invoke(cnode, method::DELETE, [index, 0, 0, 0]).map(|_| ())
}

pub fn revoke(cnode: u64, index: u64) -> Result<(), Error> {
    invoke(cnode, method::REVOKE, [index, 0, 0, 0]).map(|_| ())
}

pub fn configure(thread: u64, cnode: u64, space: u64, ipc_frame: u64, priority: u64) -> Result<(), Error> {
    invoke(thread, method::CONFIGURE, [cnode, space, ipc_frame, priority]).map(|_| ())
}

pub fn write_registers(thread: u64, pc: u64, sp: u64, arg0: u64, arg1: u64) -> Result<(), Error> {
    invoke(thread, method::WRITE_REGISTERS, [pc, sp, arg0, arg1]).map(|_| ())
}

pub fn resume(thread: u64) -> Result<(), Error> {
    invoke(thread, method::RESUME, [0; 4]).map(|_| ())
}

pub fn map(space: u64, frame: u64, va: u64, rights: u64) -> Result<(), Error> {
    invoke(space, method::MAP, [frame, va, rights, 0]).map(|_| ())
}

pub fn unmap(frame: u64) -> Result<(), Error> {
    invoke(frame, method::UNMAP, [0; 4]).map(|_| ())
}

pub fn dump_caps(debug: u64) -> Result<(), Error> {
    invoke(debug, method::DUMP_CAPS, [0; 4]).map(|_| ())
}
