//! Storage server (SPEC §B6). Holds the blk driver's endpoint and, through hostlink, the
//! byte stream the host IPC adapter uses. No network, no device capabilities.
//!
//! Slots: 1 hostlink, 4 address space, 5 blk endpoint, 6 memory server.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use aos_log::LogStorage;
use aos_rt::abi::{MsgInfo, method};
use aos_rt::cap::{map, phys};
use aos_rt::pipe::{call_chunk, unpack};
use aos_rt::println;
use aos_rt::proto;
use aos_rt::{call, ipc_buffer};
use aos_storage::wire::{self, Frame, Stat};
use aos_storage::{BlockDevice, Error, Volume};
use aos_types::Hash256;
use linked_list_allocator::LockedHeap;

aos_rt::entry!(main);

#[global_allocator]
static ALLOC: LockedHeap = LockedHeap::empty();

const LINK: u64 = 1;
const SPACE: u64 = 4;
const BLK: u64 = 5;
const MEM: u64 = 6;
const DATA: u64 = 30;
/// Above the program-frame slots the root task fills from 64 upward.
const HEAP: u64 = 128;
const HEAP_PAGES: u64 = 64;

const DATA_VA: u64 = 0x0000_5000_0000_1000;
const HEAP_VA: u64 = 0x0000_5000_0020_0000;

struct Disk {
    sectors: u64,
}

impl BlockDevice for Disk {
    type Error = ();

    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), ()> {
        xfer(false, lba, buf.as_mut_ptr(), buf.len())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), ()> {
        xfer(true, lba, buf.as_ptr() as *mut u8, buf.len())
    }

    fn flush(&mut self) -> Result<(), ()> {
        let r = call(BLK, MsgInfo::new(proto::blk::FLUSH, 0), [0; 4], 0);
        if r.is_ok() && r.words[0] == 0 { Ok(()) } else { Err(()) }
    }
}

fn xfer(write: bool, lba: u64, ptr: *mut u8, len: usize) -> Result<(), ()> {
    if len == 0 || len > 4096 || !len.is_multiple_of(512) {
        return Err(());
    }
    if write {
        // SAFETY: `ptr` is `len` bytes the caller owns; DATA_VA is the mapped transfer frame.
        unsafe { core::ptr::copy_nonoverlapping(ptr, DATA_VA as *mut u8, len) };
    }
    ipc_buffer().caps[0] = DATA;
    let label = if write { proto::blk::WRITE } else { proto::blk::READ };
    let r = call(BLK, MsgInfo::new(label, 2).with_caps(1), [lba, (len / 512) as u64, 0, 0], 0);
    if !r.is_ok() || r.words[0] != 0 {
        return Err(());
    }
    if !write {
        // SAFETY: the driver wrote `len` bytes into the transfer frame.
        unsafe { core::ptr::copy_nonoverlapping(DATA_VA as *const u8, ptr, len) };
    }
    Ok(())
}

fn alloc_frames(slot: u64, count: u64) -> u64 {
    ipc_buffer().recv_slot = slot;
    let r = call(MEM, MsgInfo::new(proto::memory::ALLOC_FRAMES, 1), [count, 0, 0, 0], 0);
    if r.is_ok() { r.info.caps() as u64 } else { 0 }
}

fn init_memory() {
    let mut done = 0u64;
    while done < HEAP_PAGES {
        let got = alloc_frames(HEAP + done, (HEAP_PAGES - done).min(3));
        if got == 0 {
            panic!("storage: memory server gave no frames");
        }
        for i in 0..got {
            map(SPACE, HEAP + done + i, HEAP_VA + (done + i) * 4096, method::WRITE).expect("map heap");
        }
        done += got;
    }
    // SAFETY: the pages just mapped are a private writable heap, and nothing has allocated yet.
    unsafe { ALLOC.lock().init(HEAP_VA as *mut u8, (HEAP_PAGES * 4096) as usize) };

    if alloc_frames(DATA, 1) != 1 {
        panic!("storage: no transfer frame");
    }
    map(SPACE, DATA, DATA_VA, method::WRITE).expect("map transfer frame");
    let _ = phys(DATA);
}

struct Host {
    buf: Vec<u8>,
}

impl Host {
    fn write_all(&mut self, bytes: &[u8]) -> bool {
        for chunk in bytes.chunks(proto::hostlink::CHUNK) {
            if !call_chunk(LINK, proto::hostlink::TX, chunk).is_ok() {
                return false;
            }
        }
        true
    }

    fn next_frame(&mut self) -> Option<Frame> {
        loop {
            match wire::decode(&mut self.buf) {
                Ok(Some(frame)) => return Some(frame),
                Ok(None) => {
                    let r = call_chunk(LINK, proto::hostlink::RX, &[]);
                    if !r.is_ok() {
                        return None;
                    }
                    let mut tmp = [0u8; proto::hostlink::CHUNK];
                    let n = unpack(r.words, &mut tmp);
                    if n == 0 {
                        return None;
                    }
                    self.buf.extend_from_slice(&tmp[..n]);
                }
                Err(_) => return None,
            }
        }
    }
}

fn stat_of(vol: &Volume<Disk>) -> Stat {
    let fault = vol.fault();
    Stat {
        read_only: vol.read_only(),
        fault: fault.map(|f| f.as_u8()).unwrap_or(0),
        fault_seq: fault.map(|f| f.seq()).unwrap_or(0),
        entries: vol.len(),
        anchor: vol.anchor().0,
    }
}

fn dispatch(vol: &mut Volume<Disk>, req: &Frame) -> Frame {
    let bad = |status| Frame::response(req.op, status, req.id, Vec::new());
    match req.op {
        wire::OP_HELLO | wire::OP_STAT => Frame::response(req.op, wire::ST_OK, req.id, stat_of(vol).encode()),
        wire::OP_LEN => Frame::response(wire::OP_LEN, wire::ST_OK, req.id, vol.len().to_le_bytes().to_vec()),
        wire::OP_READ => {
            if req.body.len() < 8 {
                return bad(wire::ST_BAD);
            }
            let seq = u64::from_le_bytes(req.body[..8].try_into().unwrap());
            match vol.read(seq) {
                Ok(bytes) => Frame::response(wire::OP_READ, wire::ST_OK, req.id, bytes),
                Err(Error::NotFound) => bad(wire::ST_NOT_FOUND),
                Err(Error::ReadOnly) => bad(wire::ST_READ_ONLY),
                Err(_) => bad(wire::ST_CORRUPT),
            }
        }
        wire::OP_APPEND => match LogStorage::append(vol, &req.body) {
            Ok(()) => bad(wire::ST_OK),
            Err(Error::Halted) => bad(wire::ST_WILL_HALT),
            Err(Error::ReadOnly) => bad(wire::ST_READ_ONLY),
            Err(Error::NoSpace) => bad(wire::ST_NO_SPACE),
            Err(_) => bad(wire::ST_BAD),
        },
        wire::OP_ARM_HALT => {
            vol.arm_halt();
            bad(wire::ST_OK)
        }
        wire::OP_SHUTDOWN => match vol.sync() {
            Ok(()) => bad(wire::ST_OK),
            Err(_) => bad(wire::ST_BAD),
        },
        wire::OP_CAS_PUT => {
            if req.body.len() < 32 {
                return bad(wire::ST_BAD);
            }
            let hash = Hash256(req.body[..32].try_into().unwrap());
            match vol.cas_put(&hash, &req.body[32..]) {
                Ok(()) => bad(wire::ST_OK),
                Err(Error::ReadOnly) => bad(wire::ST_READ_ONLY),
                Err(Error::NoSpace) => bad(wire::ST_NO_SPACE),
                Err(_) => bad(wire::ST_BAD),
            }
        }
        wire::OP_CAS_GET => {
            if req.body.len() < 32 {
                return bad(wire::ST_BAD);
            }
            let hash = Hash256(req.body[..32].try_into().unwrap());
            match vol.cas_get(&hash) {
                Ok(bytes) => Frame::response(wire::OP_CAS_GET, wire::ST_OK, req.id, bytes),
                Err(Error::NotFound) => bad(wire::ST_NOT_FOUND),
                Err(_) => bad(wire::ST_BAD),
            }
        }
        _ => bad(wire::ST_BAD),
    }
}

fn main(_: u64, _: u64) -> u64 {
    println!("storage: starting");
    init_memory();
    let r = call(BLK, MsgInfo::new(proto::blk::CAPACITY, 0), [0; 4], 0);
    if !r.is_ok() {
        println!("storage: blk driver did not answer");
        return 1;
    }
    let sectors = r.words[0] | (r.words[1] << 32);
    let mut vol = match Volume::open(Disk { sectors }) {
        Ok(v) => v,
        Err(e) => {
            println!("storage: cannot open volume: {e}");
            return 1;
        }
    };
    if let Some(fault) = vol.fault() {
        println!("storage: {fault}; read-only safe mode");
    } else {
        println!("storage: ready, {} entries", vol.len());
    }
    let mut host = Host { buf: Vec::new() };
    loop {
        let Some(req) = host.next_frame() else {
            println!("storage: host link closed");
            loop {
                core::hint::spin_loop();
            }
        };
        let resp = dispatch(&mut vol, &req);
        let halt = resp.status == wire::ST_WILL_HALT;
        if !host.write_all(&resp.encode()) {
            println!("storage: host link closed");
            loop {
                core::hint::spin_loop();
            }
        }
        if halt {
            println!("storage: halted before superblock");
            loop {
                core::hint::spin_loop();
            }
        }
    }
}
