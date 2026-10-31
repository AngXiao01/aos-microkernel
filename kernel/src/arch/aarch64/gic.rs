//! GICv2 interrupt controller (ARM IHI 0048B): distributor and CPU interface. The kernel
//! keeps only the interrupt controller and the timer (§B3.2); device interrupts will be
//! delivered to user-space drivers as notifications.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};

const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_ICPENDR: usize = 0x280;
const GICD_IPRIORITYR: usize = 0x400;
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00c;
const GICC_EOIR: usize = 0x010;

const SPURIOUS: u32 = 1023;

/// Virtual addresses of the distributor and CPU interface; 0 until `init`.
static GICD: AtomicUsize = AtomicUsize::new(0);
static GICC: AtomicUsize = AtomicUsize::new(0);

fn read(base: &AtomicUsize, reg: usize) -> u32 {
    // SAFETY: `init` stored the address of a mapped GIC register block.
    unsafe { read_volatile((base.load(Ordering::Relaxed) + reg) as *const u32) }
}

fn write(base: &AtomicUsize, reg: usize, value: u32) {
    // SAFETY: as for `read`.
    unsafe { write_volatile((base.load(Ordering::Relaxed) + reg) as *mut u32, value) }
}

/// # Safety
/// `gicd` and `gicc` must be the virtual addresses of the mapped GICv2 distributor and CPU
/// interface.
pub unsafe fn init(gicd: usize, gicc: usize) {
    GICD.store(gicd, Ordering::Relaxed);
    GICC.store(gicc, Ordering::Relaxed);
    write(&GICD, GICD_CTLR, 0);
    let lines = 32 * ((read(&GICD, GICD_TYPER) & 0x1f) as usize + 1);
    for i in 0..lines / 32 {
        write(&GICD, GICD_ICENABLER + 4 * i, u32::MAX);
        write(&GICD, GICD_ICPENDR + 4 * i, u32::MAX);
    }
    write(&GICD, GICD_CTLR, 1);
    write(&GICC, GICC_PMR, 0xff);
    write(&GICC, GICC_CTLR, 1);
}

pub fn enable(intid: u32) {
    let i = intid as usize;
    let shift = 8 * (i % 4);
    let prio = read(&GICD, GICD_IPRIORITYR + (i & !3)) & !(0xff << shift);
    write(&GICD, GICD_IPRIORITYR + (i & !3), prio | (0xa0 << shift));
    write(&GICD, GICD_ISENABLER + 4 * (i / 32), 1 << (i % 32));
}

pub fn disable(intid: u32) {
    let i = intid as usize;
    write(&GICD, GICD_ICENABLER + 4 * (i / 32), 1 << (i % 32));
}

/// Acknowledges the highest-priority pending interrupt; `None` if it was spurious.
pub fn acknowledge() -> Option<u32> {
    let iar = read(&GICC, GICC_IAR);
    if iar & 0x3ff == SPURIOUS { None } else { Some(iar) }
}

/// Ends handling of an interrupt returned by `acknowledge`.
pub fn end(iar: u32) {
    write(&GICC, GICC_EOIR, iar);
}

pub fn intid(iar: u32) -> u32 {
    iar & 0x3ff
}
