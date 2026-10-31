//! virtio-blk driver. Holds the block device's MMIO and IRQ and nothing else (§B4).
//!
//! Slot 1 service endpoint, 2 own CNode, 4 address space, 5 DeviceMMIO, 6 IRQ,
//! 7 memory server, 8 IRQ notification. The queue page is allocated from the memory server.

#![no_std]
#![no_main]

use aos_rt::abi::{Error, MsgInfo, method};
use aos_rt::cap::{delete, irq_ack, map, map_device, phys, unmap};
use aos_rt::println;
use aos_rt::proto;
use aos_rt::{call, ipc_buffer, recv, reply};
use aos_virtio::{
    BLK_F_FLUSH, BLK_T_FLUSH, BLK_T_IN, BLK_T_OUT, BlkHeader, Mmio, Queue, barrier, blk_header_pa, blk_status_pa,
};

aos_rt::entry!(main);

const EP: u64 = 1;
const CNODE: u64 = 2;
const SPACE: u64 = 4;
const MMIO_CAP: u64 = 5;
const IRQ: u64 = 6;
const MEM: u64 = 7;
const NTFN: u64 = 8;
const QFRAME: u64 = 9;
/// Frame a client lends for the transfer.
const DATA: u64 = 20;

const MMIO_VA: u64 = 0x0000_5000_0000_0000;
const Q_VA: u64 = 0x0000_5000_0000_1000;
const DATA_VA: u64 = 0x0000_5000_0000_2000;

fn alloc_frame() -> Result<(), Error> {
    ipc_buffer().recv_slot = QFRAME;
    let r = call(MEM, MsgInfo::new(proto::memory::ALLOC_FRAMES, 1), [1, 0, 0, 0], 0);
    if r.is_ok() && r.info.caps() >= 1 { Ok(()) } else { Err(Error::NoMemory) }
}

fn wait_done(q: &mut Queue<4>, mmio: &Mmio) {
    for _ in 0..100 {
        if q.completed() {
            q.advance();
            mmio.ack_interrupt();
            let _ = irq_ack(IRQ);
            return;
        }
        let _ = aos_rt::wait(NTFN, 20_000_000);
        mmio.ack_interrupt();
        let _ = irq_ack(IRQ);
    }
    panic!("blk: request timed out");
}

fn header(kind: u32, sector: u64) {
    let h = (Q_VA + 0x200) as *mut BlkHeader;
    let status = (Q_VA + 0x210) as *mut u8;
    // SAFETY: both addresses are in the queue page this driver mapped.
    unsafe {
        core::ptr::write_volatile(&mut (*h).typ, kind);
        core::ptr::write_volatile(&mut (*h).reserved, 0);
        core::ptr::write_volatile(&mut (*h).sector, sector);
        core::ptr::write_volatile(status, 0xff);
    }
    barrier();
}

fn status_byte() -> u8 {
    // SAFETY: the status byte lives in the queue page.
    unsafe { core::ptr::read_volatile((Q_VA + 0x210) as *const u8) }
}

fn main(mmio_off: u64, _: u64) -> u64 {
    if let Err(e) = map_device(SPACE, MMIO_CAP, MMIO_VA) {
        println!("blk: cannot map device: {e:?}");
        return 1;
    }
    let mmio_va = MMIO_VA + mmio_off;
    if alloc_frame().is_err() || map(SPACE, QFRAME, Q_VA, method::WRITE).is_err() {
        println!("blk: no queue page");
        return 1;
    }
    let pa = phys(QFRAME).unwrap_or(0);
    // SAFETY: the queue page was just mapped read/write at Q_VA.
    unsafe { core::ptr::write_bytes(Q_VA as *mut u8, 0, 4096) };

    let mmio = Mmio::new(mmio_va);
    if mmio.device_id() != aos_virtio::DEV_BLK {
        println!("blk: device id {} is not virtio-blk", mmio.device_id());
        return 1;
    }
    if let Err(e) = mmio.negotiate(BLK_F_FLUSH) {
        println!("blk: {e}");
        return 1;
    }
    let mut q: Queue<4> = Queue::new(Q_VA, pa, 0);
    if let Err(e) = q.install(&mmio, 0) {
        println!("blk: {e}");
        return 1;
    }
    mmio.finish();
    let sectors = mmio.config_u64(0);
    println!("blk: ready, {sectors} sectors");

    let header_pa = blk_header_pa(pa);
    let status_pa = blk_status_pa(pa);
    ipc_buffer().recv_slot = DATA;
    loop {
        let r = recv(EP, 0);
        if !r.is_ok() {
            continue;
        }
        let fail = |label| reply(MsgInfo::new(label, 1), [1, 0, 0, 0]);
        match r.info.label() {
            proto::blk::CAPACITY => {
                reply(MsgInfo::new(proto::blk::CAPACITY, 2), [sectors, sectors >> 32, 0, 0]);
            }
            proto::blk::FLUSH => {
                header(BLK_T_FLUSH, 0);
                q.submit_flush(&mmio, header_pa, status_pa);
                wait_done(&mut q, &mmio);
                let bad = u64::from(status_byte() != 0);
                reply(MsgInfo::new(proto::blk::FLUSH, 1), [bad, 0, 0, 0]);
            }
            label @ (proto::blk::READ | proto::blk::WRITE) => {
                if r.info.caps() < 1 {
                    fail(label);
                    continue;
                }
                let lba = r.words[0];
                let count = r.words[1].clamp(1, 8) as u32;
                if map(SPACE, DATA, DATA_VA, method::WRITE).is_err() {
                    fail(label);
                    continue;
                }
                let data_pa = phys(DATA).unwrap_or(0);
                let write = label == proto::blk::WRITE;
                header(if write { BLK_T_OUT } else { BLK_T_IN }, lba);
                q.submit_blk(&mmio, header_pa, data_pa, count * 512, status_pa, write);
                wait_done(&mut q, &mmio);
                let bad = u64::from(status_byte() != 0);
                let _ = unmap(DATA);
                let _ = delete(CNODE, DATA);
                reply(MsgInfo::new(label, 1), [bad, 0, 0, 0]);
            }
            _ => {
                reply(MsgInfo::new(proto::memory::UNKNOWN, 0), [0; 4]);
            }
        }
    }
}
