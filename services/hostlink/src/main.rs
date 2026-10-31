//! virtio-console, port 0. The storage server is the only client. The host speaks the
//! storage protocol through the socket QEMU attaches to this console (§B10).

#![no_std]
#![no_main]

use aos_rt::abi::{MsgInfo, method};
use aos_rt::cap::{irq_ack, map, map_device, phys};
use aos_rt::pipe::{reply_chunk, unpack};
use aos_rt::println;
use aos_rt::proto;
use aos_rt::{call, ipc_buffer, recv};
use aos_virtio::{Mmio, Queue};

aos_rt::entry!(main);

const EP: u64 = 1;
const SPACE: u64 = 4;
const MMIO_CAP: u64 = 5;
const IRQ: u64 = 6;
const MEM: u64 = 7;
const NTFN: u64 = 8;
const QFRAME: u64 = 9;

const MMIO_VA: u64 = 0x0000_5000_0000_0000;
const Q_VA: u64 = 0x0000_5000_0000_1000;
const RX_OFF: u64 = 0x400;
const TX_OFF: u64 = 0x800;
const BUF: u32 = 1024;

fn main(mmio_off: u64, _: u64) -> u64 {
    if let Err(e) = map_device(SPACE, MMIO_CAP, MMIO_VA) {
        println!("hostlink: cannot map device: {e:?}");
        return 1;
    }
    let mmio_va = MMIO_VA + mmio_off;
    ipc_buffer().recv_slot = QFRAME;
    let got = call(MEM, MsgInfo::new(proto::memory::ALLOC_FRAMES, 1), [1, 0, 0, 0], 0);
    if !got.is_ok() || got.info.caps() < 1 || map(SPACE, QFRAME, Q_VA, method::WRITE).is_err() {
        println!("hostlink: no queue page");
        return 1;
    }
    let pa = phys(QFRAME).unwrap_or(0);
    // SAFETY: the queue page was just mapped writable.
    unsafe { core::ptr::write_bytes(Q_VA as *mut u8, 0, 4096) };

    let mmio = Mmio::new(mmio_va);
    if mmio.device_id() != aos_virtio::DEV_CONSOLE {
        println!("hostlink: device id {} is not virtio-console", mmio.device_id());
        return 1;
    }
    if let Err(e) = mmio.negotiate(0) {
        println!("hostlink: {e}");
        return 1;
    }
    let mut rx: Queue<4> = Queue::new(Q_VA, pa, 0);
    let mut tx: Queue<4> = Queue::new(Q_VA, pa, 256);
    if rx.install(&mmio, 0).and(tx.install(&mmio, 1)).is_err() {
        println!("hostlink: queue setup failed");
        return 1;
    }
    rx.submit_buf(&mmio, 0, pa + RX_OFF, BUF, false);
    mmio.finish();
    println!("hostlink: ready");

    let mut ring = [0u8; 8192];
    let mut head = 0usize;
    let mut tail = 0usize;
    let mut tx_busy = false;

    let pump = |mmio: &Mmio,
                rx: &mut Queue<4>,
                tx: &mut Queue<4>,
                ring: &mut [u8],
                head: &mut usize,
                tail: &mut usize,
                tx_busy: &mut bool| {
        mmio.ack_interrupt();
        let _ = irq_ack(IRQ);
        if rx.completed() {
            let n = rx.advance() as usize;
            let n = n.min(BUF as usize);
            // SAFETY: the receive buffer is in the queue page at RX_OFF.
            let src = unsafe { core::slice::from_raw_parts((Q_VA + RX_OFF) as *const u8, n) };
            for &b in src {
                let next = (*head + 1) % ring.len();
                if next != *tail {
                    ring[*head] = b;
                    *head = next;
                }
            }
            rx.submit_buf(mmio, 0, pa + RX_OFF, BUF, false);
        }
        if tx.completed() {
            tx.advance();
            *tx_busy = false;
        }
    };

    loop {
        pump(&mmio, &mut rx, &mut tx, &mut ring, &mut head, &mut tail, &mut tx_busy);
        let pending = if head >= tail { head - tail } else { ring.len() - tail + head };
        let r = recv(EP, 0);
        if !r.is_ok() {
            continue;
        }
        match r.info.label() {
            proto::hostlink::TX => {
                let mut buf = [0u8; proto::hostlink::CHUNK];
                let n = unpack(r.words, &mut buf);
                while tx_busy {
                    let _ = aos_rt::wait(NTFN, 20_000_000);
                    pump(&mmio, &mut rx, &mut tx, &mut ring, &mut head, &mut tail, &mut tx_busy);
                }
                let n = n.min(BUF as usize);
                // SAFETY: the transmit buffer is in the queue page at TX_OFF.
                unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), (Q_VA + TX_OFF) as *mut u8, n) };
                tx_busy = true;
                tx.submit_buf(&mmio, 1, pa + TX_OFF, n as u32, true);
                while tx_busy {
                    let _ = aos_rt::wait(NTFN, 20_000_000);
                    pump(&mmio, &mut rx, &mut tx, &mut ring, &mut head, &mut tail, &mut tx_busy);
                }
                reply_chunk(proto::hostlink::TX, &[]);
            }
            proto::hostlink::RX => {
                while head == tail {
                    let _ = aos_rt::wait(NTFN, 0);
                    pump(&mmio, &mut rx, &mut tx, &mut ring, &mut head, &mut tail, &mut tx_busy);
                }
                let mut buf = [0u8; proto::hostlink::CHUNK];
                let mut n = 0;
                while n < buf.len() && tail != head {
                    buf[n] = ring[tail];
                    tail = (tail + 1) % ring.len();
                    n += 1;
                }
                reply_chunk(proto::hostlink::RX, &buf[..n]);
            }
            _ => {
                aos_rt::reply(MsgInfo::new(proto::memory::UNKNOWN, 0), [0; 4]);
            }
        }
        let _ = pending;
    }
}
