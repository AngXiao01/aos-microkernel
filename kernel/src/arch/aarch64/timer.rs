//! The EL1 non-secure physical timer (CNTP) and the system counter: the kernel's tick and
//! monotonic clock (§B3.1).

use core::arch::asm;

/// INTID of the EL1 non-secure physical timer: PPI 14.
pub const INTID: u32 = 30;

/// Counter ticks per second.
pub fn frequency() -> u64 {
    let f: u64;
    // SAFETY: reading CNTFRQ_EL0 has no side effects.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack, preserves_flags)) };
    f
}

/// The monotonic system counter.
pub fn now() -> u64 {
    let t: u64;
    // SAFETY: reading CNTPCT_EL0 has no side effects; the isb orders it after earlier code.
    unsafe { asm!("isb", "mrs {}, cntpct_el0", out(reg) t, options(nomem, nostack, preserves_flags)) };
    t
}

/// Fires the timer interrupt `ticks` counter ticks from now (this also clears a pending one).
pub fn arm(ticks: u64) {
    let ticks = ticks.min(i32::MAX as u64);
    // SAFETY: programs the EL1 physical timer, which belongs to the kernel.
    unsafe {
        asm!(
            "msr cntp_tval_el0, {}",
            "msr cntp_ctl_el0, {}",
            "isb",
            in(reg) ticks,
            in(reg) 1u64,
            options(nomem, nostack, preserves_flags),
        )
    };
}

pub fn ns_to_ticks(ns: u64) -> u64 {
    (u128::from(ns) * u128::from(frequency()) / 1_000_000_000) as u64
}
