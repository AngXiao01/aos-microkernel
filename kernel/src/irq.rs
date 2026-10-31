//! Interrupts. They arrive either as an exit from a user thread (EL0 vector) or at EL1
//! while the kernel idles. Either way the handler only acknowledges them and records what
//! happened; the run loop acts on it, so interrupt handlers never touch kernel objects.
//!
//! Device interrupts are disabled in the GIC until a driver binds a notification, then
//! disabled again until the driver acknowledges them. The handler records which slot
//! fired; the run loop signals the notification.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::{gic, timer};
use crate::ipc::Notification;
use crate::kobj::KPtr;

pub const TICK_HZ: u64 = 1000;
pub const SLOTS: usize = 4;

static TICKS: AtomicU64 = AtomicU64::new(0);
static TICK_PERIOD: AtomicU64 = AtomicU64::new(0);
/// Bit i is set when device slot i fired. The handler sets bits; the run loop clears them.
static PENDING: AtomicU32 = AtomicU32::new(0);
/// GIC intid for each slot. The handler reads these; only the run loop writes them.
static INTIDS: [AtomicU32; SLOTS] = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

struct Binding {
    ntfn: Option<KPtr<Notification>>,
}

/// Notification bindings. Touched only from the run loop, never from the handler, so it
/// needs no lock (the handler only reads [`INTIDS`] and [`PENDING`]).
struct IrqTable(UnsafeCell<[Binding; SLOTS]>);
// SAFETY: the run loop is the only mutator; interrupt handlers do not touch it.
unsafe impl Sync for IrqTable {}

static BINDINGS: IrqTable = IrqTable(UnsafeCell::new([
    Binding { ntfn: None },
    Binding { ntfn: None },
    Binding { ntfn: None },
    Binding { ntfn: None },
]));

fn bindings() -> &'static mut [Binding; SLOTS] {
    // SAFETY: see `IrqTable`.
    unsafe { &mut *BINDINGS.0.get() }
}

/// Records which GIC interrupt a slot delivers. The line stays masked until [`bind`].
pub fn register(index: usize, intid: u32) {
    INTIDS[index].store(intid, Ordering::Relaxed);
}

/// Signals `ntfn` (bit 1) from the run loop whenever this interrupt fires, and unmasks it.
pub fn bind(index: usize, ntfn: KPtr<Notification>) {
    bindings()[index].ntfn = Some(ntfn);
    let intid = INTIDS[index].load(Ordering::Relaxed);
    if intid != 0 {
        gic::enable(intid);
    }
}

/// Drops the binding and masks the line. Called when the IRQ capability is deleted.
pub fn unbind(index: usize) {
    bindings()[index].ntfn = None;
    let intid = INTIDS[index].load(Ordering::Relaxed);
    if intid != 0 {
        gic::disable(intid);
    }
}

/// Unmasks the line after the driver has acknowledged the device.
pub fn ack(index: usize) {
    let intid = INTIDS[index].load(Ordering::Relaxed);
    if intid != 0 {
        gic::enable(intid);
    }
}

pub fn notification(index: usize) -> Option<KPtr<Notification>> {
    bindings()[index].ntfn
}

/// Bits set by the handler since the last call.
pub fn take_pending() -> u32 {
    PENDING.swap(0, Ordering::Relaxed)
}

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
            other => {
                gic::disable(other);
                if let Some(index) = (0..SLOTS).find(|&i| INTIDS[i].load(Ordering::Relaxed) == other) {
                    PENDING.fetch_or(1 << index, Ordering::Relaxed);
                } else {
                    crate::console::print_unlocked(format_args!("irq: unexpected interrupt {other}\n"));
                }
            }
        }
        gic::end(iar);
    }
}

/// Ticks since the last call.
pub fn take_ticks() -> u64 {
    TICKS.swap(0, Ordering::Relaxed)
}
