//! virtio over MMIO, version 1.0 (SPEC §B2: QEMU's virtio-mmio only).
//!
//! One queue, one outstanding request. Descriptor rings live in a single page the caller
//! owns; this crate never allocates.

#![no_std]

use core::ptr::{read_volatile, write_volatile};

pub const MAGIC: u32 = 0x7472_6976;
pub const DEV_BLK: u32 = 2;
pub const DEV_CONSOLE: u32 = 3;

const ACK: u32 = 1;
const DRIVER: u32 = 2;
const DRIVER_OK: u32 = 4;
const FEATURES_OK: u32 = 8;
const VERSION_1: u32 = 1;

const REG_MAGIC: usize = 0x000;
const REG_VERSION: usize = 0x004;
const REG_DEVICE_ID: usize = 0x008;
const REG_FEATURES: usize = 0x010;
const REG_FEATURES_SEL: usize = 0x014;
const REG_DRIVER_FEATURES: usize = 0x020;
const REG_DRIVER_FEATURES_SEL: usize = 0x024;
const REG_QUEUE_SEL: usize = 0x030;
const REG_QUEUE_NUM_MAX: usize = 0x034;
const REG_QUEUE_NUM: usize = 0x038;
const REG_QUEUE_READY: usize = 0x044;
const REG_QUEUE_NOTIFY: usize = 0x050;
const REG_INT_STATUS: usize = 0x060;
const REG_INT_ACK: usize = 0x064;
const REG_STATUS: usize = 0x070;
const REG_DESC_LOW: usize = 0x080;
const REG_DESC_HIGH: usize = 0x084;
const REG_AVAIL_LOW: usize = 0x090;
const REG_AVAIL_HIGH: usize = 0x094;
const REG_USED_LOW: usize = 0x0a0;
const REG_USED_HIGH: usize = 0x0a4;
const REG_CONFIG: usize = 0x100;

const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;

pub fn barrier() {
    // SAFETY: a barrier has no memory operands the compiler needs to know about.
    unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)) };
}

pub struct Mmio {
    base: *mut u8,
}

impl Mmio {
    /// `va` is a mapping of the device page.
    pub fn new(va: u64) -> Mmio {
        Mmio { base: va as *mut u8 }
    }

    fn read(&self, off: usize) -> u32 {
        // SAFETY: `off` is a 32-bit MMIO register in the mapped page.
        unsafe { read_volatile(self.base.add(off) as *const u32) }
    }

    fn write(&self, off: usize, value: u32) {
        // SAFETY: as for `read`.
        unsafe { write_volatile(self.base.add(off) as *mut u32, value) }
    }

    pub fn magic(&self) -> u32 {
        self.read(REG_MAGIC)
    }

    pub fn version(&self) -> u32 {
        self.read(REG_VERSION)
    }

    pub fn device_id(&self) -> u32 {
        self.read(REG_DEVICE_ID)
    }

    pub fn config_u64(&self, off: usize) -> u64 {
        let lo = self.read(REG_CONFIG + off) as u64;
        let hi = self.read(REG_CONFIG + off + 4) as u64;
        lo | (hi << 32)
    }

    /// Acknowledges the device interrupt. Returns the status bits that were set.
    pub fn ack_interrupt(&self) -> u32 {
        let status = self.read(REG_INT_STATUS);
        if status != 0 {
            self.write(REG_INT_ACK, status);
        }
        status
    }

    /// Negotiates version 1 and `device_features` (low word, masked by what the device
    /// offers). Queues are added next, then [`finish`].
    pub fn negotiate(&self, device_features: u32) -> Result<(), &'static str> {
        if self.magic() != MAGIC || self.version() != 2 {
            return Err("not virtio-mmio 1.0");
        }
        self.write(REG_STATUS, 0);
        self.write(REG_STATUS, ACK);
        self.write(REG_STATUS, ACK | DRIVER);
        self.write(REG_FEATURES_SEL, 0);
        let offered = self.read(REG_FEATURES);
        self.write(REG_DRIVER_FEATURES_SEL, 0);
        self.write(REG_DRIVER_FEATURES, offered & device_features);
        self.write(REG_DRIVER_FEATURES_SEL, 1);
        self.write(REG_DRIVER_FEATURES, VERSION_1);
        barrier();
        self.write(REG_STATUS, ACK | DRIVER | FEATURES_OK);
        if self.read(REG_STATUS) & FEATURES_OK == 0 {
            return Err("device rejected features");
        }
        Ok(())
    }

    pub fn finish(&self) {
        let status = self.read(REG_STATUS);
        self.write(REG_STATUS, status | DRIVER_OK);
    }

    pub fn notify(&self, queue: u32) {
        barrier();
        self.write(REG_QUEUE_NOTIFY, queue);
    }

    fn setup_queue(&self, index: u32, size: u16, desc: u64, avail: u64, used: u64) -> Result<(), &'static str> {
        self.write(REG_QUEUE_SEL, index);
        if self.read(REG_QUEUE_READY) != 0 {
            return Err("queue already ready");
        }
        let max = self.read(REG_QUEUE_NUM_MAX);
        if max == 0 || u32::from(size) > max {
            return Err("queue too large");
        }
        self.write(REG_QUEUE_NUM, u32::from(size));
        self.write(REG_DESC_LOW, desc as u32);
        self.write(REG_DESC_HIGH, (desc >> 32) as u32);
        self.write(REG_AVAIL_LOW, avail as u32);
        self.write(REG_AVAIL_HIGH, (avail >> 32) as u32);
        self.write(REG_USED_LOW, used as u32);
        self.write(REG_USED_HIGH, (used >> 32) as u32);
        barrier();
        self.write(REG_QUEUE_READY, 1);
        Ok(())
    }
}

#[repr(C)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// A queue of `SIZE` descriptors inside a caller-provided page, at `offset`.
pub struct Queue<const SIZE: usize> {
    va: usize,
    pa: u64,
    offset: usize,
    last_used: u16,
}

impl<const SIZE: usize> Queue<SIZE> {
    pub fn new(va: u64, pa: u64, offset: usize) -> Queue<SIZE> {
        Queue { va: va as usize, pa, offset, last_used: 0 }
    }

    fn addr(&self, add: usize) -> usize {
        self.va + self.offset + add
    }

    pub fn install(&self, mmio: &Mmio, index: u32) -> Result<(), &'static str> {
        let desc = self.pa + self.offset as u64;
        let avail = desc + 128;
        let used = desc + 192;
        mmio.setup_queue(index, SIZE as u16, desc, avail, used)
    }

    fn write_desc(&self, i: usize, addr: u64, len: u32, flags: u16, next: u16) {
        let d = self.addr(i * 16) as *mut Desc;
        // SAFETY: the descriptor table sits in the caller's queue page.
        unsafe {
            write_volatile(&mut (*d).addr, addr);
            write_volatile(&mut (*d).len, len);
            write_volatile(&mut (*d).flags, flags);
            write_volatile(&mut (*d).next, next);
        }
    }

    fn push(&mut self, head: u16, mmio: &Mmio, queue: u32) {
        let avail = self.addr(128) as *mut u16;
        // SAFETY: available ring at offset 128 of this queue's slice: flags, idx, ring[SIZE].
        unsafe {
            let idx = read_volatile(avail.add(1));
            write_volatile(avail.add(2 + (idx as usize % SIZE)), head);
            barrier();
            write_volatile(avail.add(1), idx.wrapping_add(1));
        }
        mmio.notify(queue);
    }

    pub fn completed(&self) -> bool {
        let used = self.addr(192) as *const u16;
        // SAFETY: used ring header (flags, idx) at offset 192.
        let idx = unsafe { read_volatile(used.add(1)) };
        barrier();
        idx != self.last_used
    }

    pub fn advance(&mut self) -> u32 {
        let used = self.addr(192) as *const u8;
        let slot = self.last_used as usize % SIZE;
        // SAFETY: used elem is 8 bytes at header+4 + slot*8.
        let len = unsafe { read_volatile(used.add(4 + slot * 8 + 4) as *const u32) };
        self.last_used = self.last_used.wrapping_add(1);
        len
    }

    /// Flush: header then status. A data descriptor makes QEMU's virtio-blk never complete.
    pub fn submit_flush(&mut self, mmio: &Mmio, header_pa: u64, status_pa: u64) {
        self.write_desc(0, header_pa, 16, DESC_NEXT, 1);
        self.write_desc(1, status_pa, 1, DESC_WRITE, 0);
        self.push(0, mmio, 0);
    }

    /// Block request: header (device reads), data, status byte (device writes).
    pub fn submit_blk(
        &mut self,
        mmio: &Mmio,
        header_pa: u64,
        data_pa: u64,
        data_len: u32,
        status_pa: u64,
        to_device: bool,
    ) {
        let data_flags = if to_device { DESC_NEXT } else { DESC_WRITE | DESC_NEXT };
        self.write_desc(0, header_pa, 16, DESC_NEXT, 1);
        self.write_desc(1, data_pa, data_len, data_flags, 2);
        self.write_desc(2, status_pa, 1, DESC_WRITE, 0);
        self.push(0, mmio, 0);
    }

    /// One-buffer console transfer. `to_device` is a transmit.
    pub fn submit_buf(&mut self, mmio: &Mmio, queue: u32, buf_pa: u64, len: u32, to_device: bool) {
        let flags = if to_device { 0 } else { DESC_WRITE };
        self.write_desc(0, buf_pa, len, flags, 0);
        self.push(0, mmio, queue);
    }
}

pub const BLK_T_IN: u32 = 0;
pub const BLK_T_OUT: u32 = 1;
pub const BLK_T_FLUSH: u32 = 4;
/// Flush command.
pub const BLK_F_FLUSH: u32 = 1 << 9;

#[repr(C)]
pub struct BlkHeader {
    pub typ: u32,
    pub reserved: u32,
    pub sector: u64,
}

/// Header and status byte placed after the queue structures in the same page.
pub fn blk_header_pa(queue_pa: u64) -> u64 {
    queue_pa + 0x200
}

pub fn blk_status_pa(queue_pa: u64) -> u64 {
    queue_pa + 0x210
}
