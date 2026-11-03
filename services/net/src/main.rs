//! virtio-net driver. Holds the NIC's MMIO and IRQ and talks only to the netstack (§B4).
//!
//! Slots match the block driver: 1 service endpoint, 4 address space, 5 DeviceMMIO, 6 IRQ,
//! 7 memory server, 8 IRQ notification.

#![no_std]
#![no_main]

use aos_rt::abi::{MsgInfo, method};
use aos_rt::cap::{delete, irq_ack, map, map_device, phys, unmap};
use aos_rt::println;
use aos_rt::proto;
use aos_rt::{call, ipc_buffer, recv, reply};
use aos_virtio::{Mmio, Queue};

aos_rt::entry!(main);

const EP: u64 = 1;
const CNODE: u64 = 2;
const SPACE: u64 = 4;
const MMIO_CAP: u64 = 5;
const IRQ: u64 = 6;
const MEM: u64 = 7;
const NTFN: u64 = 8;
const QFRAME: u64 = 9;
const BUFFRAME: u64 = 10;
const DATA: u64 = 20;

const MMIO_VA: u64 = 0x0000_5000_0000_0000;
const Q_VA: u64 = 0x0000_5000_0000_1000;
const BUF_VA: u64 = 0x0000_5000_0000_2000;
const DATA_VA: u64 = 0x0000_5000_0000_3000;

/// QEMU 8.2's virtio-net backend consumes a 12-byte header (`virtio_net_hdr_mrg_rxbuf`)
/// even when the guest does not ack VIRTIO_NET_F_MRG_RXBUF. A 10-byte header shifts the
/// ethernet frame by two bytes and slirp drops it. The extra `num_buffers` field is zero.
const HDR: usize = 12;
const F_MAC: u32 = 1 << 5;
const MAX_FRAME: usize = 1514;

fn alloc(slot: u64) -> bool {
    ipc_buffer().recv_slot = slot;
    let r = call(MEM, MsgInfo::new(proto::memory::ALLOC_FRAMES, 1), [1, 0, 0, 0], 0);
    r.is_ok() && r.info.caps() >= 1
}

struct Nic {
    mmio: Mmio,
    rx: Queue<4>,
    tx: Queue<4>,
    buf_pa: u64,
}

impl Nic {
    fn pump(&mut self, queue: &mut PacketQueue) {
        self.mmio.ack_interrupt();
        let _ = irq_ack(IRQ);
        if self.rx.completed() {
            let n = self.rx.advance() as usize;
            if n > HDR {
                let take = (n - HDR).min(MAX_FRAME);
                // SAFETY: the receive buffer is the first half of the buffer frame.
                let src = unsafe { core::slice::from_raw_parts((BUF_VA as *const u8).add(HDR), take) };
                queue.push(src);
            }
            self.rx.submit_buf(&self.mmio, 0, self.buf_pa, 2048, false);
        }
        if self.tx.completed() {
            self.tx.advance();
        }
    }

    fn transmit(&mut self, frame: &[u8]) {
        let n = frame.len().min(MAX_FRAME);
        // SAFETY: transmit buffer starts at 2048 in the buffer frame; header + frame fit.
        unsafe {
            let dst = (BUF_VA as *mut u8).add(2048);
            core::ptr::write_bytes(dst, 0, HDR);
            core::ptr::copy_nonoverlapping(frame.as_ptr(), dst.add(HDR), n);
        }
        self.tx.submit_buf(&self.mmio, 1, self.buf_pa + 2048, (HDR + n) as u32, true);
        for _ in 0..50 {
            if self.tx.completed() {
                self.tx.advance();
                self.mmio.ack_interrupt();
                let _ = irq_ack(IRQ);
                return;
            }
            let _ = aos_rt::wait(NTFN, 2_000_000);
            self.mmio.ack_interrupt();
            let _ = irq_ack(IRQ);
        }
        println!("net: tx timeout");
    }
}

struct PacketQueue {
    buf: [[u8; MAX_FRAME]; 8],
    len: [usize; 8],
    head: usize,
    tail: usize,
}

impl PacketQueue {
    const fn new() -> PacketQueue {
        PacketQueue { buf: [[0; MAX_FRAME]; 8], len: [0; 8], head: 0, tail: 0 }
    }

    fn push(&mut self, frame: &[u8]) {
        let next = (self.head + 1) % 8;
        if next == self.tail {
            return; // drop when the netstack is behind
        }
        self.buf[self.head][..frame.len()].copy_from_slice(frame);
        self.len[self.head] = frame.len();
        self.head = next;
    }

    fn pop_into(&mut self, dst: &mut [u8]) -> usize {
        if self.tail == self.head {
            return 0;
        }
        let n = self.len[self.tail];
        dst[..n].copy_from_slice(&self.buf[self.tail][..n]);
        self.tail = (self.tail + 1) % 8;
        n
    }
}

fn main(mmio_off: u64, _: u64) -> u64 {
    if map_device(SPACE, MMIO_CAP, MMIO_VA).is_err() || !alloc(QFRAME) || !alloc(BUFFRAME) {
        println!("net: setup failed");
        return 1;
    }
    if map(SPACE, QFRAME, Q_VA, method::WRITE).is_err() || map(SPACE, BUFFRAME, BUF_VA, method::WRITE).is_err() {
        println!("net: map failed");
        return 1;
    }
    let q_pa = phys(QFRAME).unwrap_or(0);
    let buf_pa = phys(BUFFRAME).unwrap_or(0);
    unsafe {
        core::ptr::write_bytes(Q_VA as *mut u8, 0, 4096);
        core::ptr::write_bytes(BUF_VA as *mut u8, 0, 4096);
    }
    let mmio = Mmio::new(MMIO_VA + mmio_off);
    if mmio.device_id() != 1 {
        println!("net: device id {} is not virtio-net", mmio.device_id());
        return 1;
    }
    if mmio.negotiate(F_MAC).is_err() {
        println!("net: negotiate failed");
        return 1;
    }
    let mut rx = Queue::<4>::new(Q_VA, q_pa, 0);
    let tx = Queue::<4>::new(Q_VA, q_pa, 256);
    if rx.install(&mmio, 0).and(tx.install(&mmio, 1)).is_err() {
        println!("net: queues failed");
        return 1;
    }
    rx.submit_buf(&mmio, 0, buf_pa, 2048, false);
    mmio.finish();
    let w0 = mmio_u32(MMIO_VA + mmio_off, 0x100);
    let w1 = mmio_u32(MMIO_VA + mmio_off, 0x104);
    let mac = [w0 as u8, (w0 >> 8) as u8, (w0 >> 16) as u8, (w0 >> 24) as u8, w1 as u8, (w1 >> 8) as u8];
    println!(
        "net: ready mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    let mut nic = Nic { mmio, rx, tx, buf_pa };
    let mut queue = PacketQueue::new();
    ipc_buffer().recv_slot = DATA;
    loop {
        nic.pump(&mut queue);
        let r = recv(EP, 1_000_000);
        if !r.is_ok() {
            continue;
        }
        match r.info.label() {
            proto::net::MAC => {
                let lo = u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], 0, 0, 0, 0]);
                let hi = u64::from(u16::from_le_bytes([mac[4], mac[5]]));
                reply(MsgInfo::new(proto::net::MAC, 2), [lo, hi, 0, 0]);
            }
            proto::net::TX => {
                if r.info.caps() < 1 {
                    reply(MsgInfo::new(proto::net::TX, 1), [1, 0, 0, 0]);
                    continue;
                }
                let n = (r.words[0] as usize).min(MAX_FRAME);
                if map(SPACE, DATA, DATA_VA, method::WRITE).is_ok() {
                    let mut frame = [0u8; MAX_FRAME];
                    unsafe { core::ptr::copy_nonoverlapping(DATA_VA as *const u8, frame.as_mut_ptr(), n) };
                    let _ = unmap(DATA);
                    let _ = delete(CNODE, DATA);
                    nic.transmit(&frame[..n]);
                    reply(MsgInfo::new(proto::net::TX, 1), [0, 0, 0, 0]);
                } else {
                    reply(MsgInfo::new(proto::net::TX, 1), [1, 0, 0, 0]);
                }
            }
            proto::net::RX => {
                if r.info.caps() < 1 {
                    reply(MsgInfo::new(proto::net::RX, 1), [0, 0, 0, 0]);
                    continue;
                }
                nic.pump(&mut queue);
                if queue.tail == queue.head {
                    // Slirp and the public peer are slower than a tight poll. Block on the
                    // virtio interrupt briefly so TCP retransmits and DNS have a chance.
                    let _ = aos_rt::wait(NTFN, 2_000_000);
                    nic.pump(&mut queue);
                }
                let mut frame = [0u8; MAX_FRAME];
                let n = queue.pop_into(&mut frame);
                if map(SPACE, DATA, DATA_VA, method::WRITE).is_ok() {
                    if n > 0 {
                        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), DATA_VA as *mut u8, n) };
                    }
                    let _ = unmap(DATA);
                    let _ = delete(CNODE, DATA);
                }
                reply(MsgInfo::new(proto::net::RX, 1), [n as u64, 0, 0, 0]);
            }
            _ => {
                reply(MsgInfo::new(0xfff, 0), [0; 4]);
            }
        }
    }
}

fn mmio_u32(va: u64, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((va as *const u8).add(off) as *const u32) }
}
