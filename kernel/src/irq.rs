//! Interrupts. They arrive either as an exit from a user thread (EL0 vector) or at EL1
//! while the kernel idles. Either way the handler only acknowledges them and records what
//! happened; the run loop acts on it, so interrupt handlers never touch kernel objects.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{gic, timer};

pub const TICK_HZ: u64 = 1000;

static TICKS: AtomicU64 = AtomicU64::new(0);
static TICK_PERIOD: AtomicU64 = AtomicU64::new(0);

/// # Safety
/// `gicd` and `gicc` must be the mapped GICv2 distributor and CPU interface.
pub unsafe fn init(gicd: usize, gicc: usize) {
    // SAFETY: guaranteed by the caller.
    unsafe { gic::init(gicd, gicc) };
    gic::enable(timer::INTID);
    let period = timer::frequency() / TICK_HZ;
    TICK_PERIOD.store(period, Ordering::Relaxed);
    timer::arm(period);
}

pub fn handle() {
    while let Some(iar) = gic::acknowledge() {
        match gic::intid(iar) {
            timer::INTID => {
                timer::arm(TICK_PERIOD.load(Ordering::Relaxed));
                TICKS.fetch_add(1, Ordering::Relaxed);
            }
            other => crate::console::print_unlocked(format_args!("irq: unexpected interrupt {other}\n")),
        }
        gic::end(iar);
    }
}

/// Ticks since the last call.
pub fn take_ticks() -> u64 {
    TICKS.swap(0, Ordering::Relaxed)
}
