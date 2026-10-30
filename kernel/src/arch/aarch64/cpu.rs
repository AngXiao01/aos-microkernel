//! CPU registers and control.

use core::arch::asm;

macro_rules! read_sysreg {
    ($name:ident, $reg:literal) => {
        pub fn $name() -> u64 {
            let value: u64;
            // SAFETY: reading this system register at EL1 has no side effects.
            unsafe { asm!(concat!("mrs {}, ", $reg), out(reg) value, options(nomem, nostack, preserves_flags)) };
            value
        }
    };
}

read_sysreg!(esr_el1, "esr_el1");
read_sysreg!(far_el1, "far_el1");
read_sysreg!(sctlr_el1, "sctlr_el1");

pub fn current_el() -> u64 {
    let el: u64;
    // SAFETY: CurrentEL is readable at every exception level above EL0.
    unsafe { asm!("mrs {}, CurrentEL", out(reg) el, options(nomem, nostack, preserves_flags)) };
    (el >> 2) & 3
}

pub fn halt() -> ! {
    loop {
        // SAFETY: waiting for an event has no other effect.
        unsafe { asm!("wfe", options(nomem, nostack, preserves_flags)) };
    }
}
