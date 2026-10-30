//! Exception vectors and dispatch.
//!
//! Every vector saves the full register state in a [`TrapFrame`] on the current stack and
//! calls [`trap_dispatch`], which may modify the frame before it is restored. In B-0 the
//! only recoverable exceptions are faults raised by [`super::probe`]; everything else is
//! a kernel bug and panics.

use super::{cpu, probe};

#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr: u64,
    pub spsr: u64,
}

const _: () = assert!(size_of::<TrapFrame>() == 34 * 8);

core::arch::global_asm!(
    r#"
.macro VECTOR kind
.balign 0x80
    sub     sp, sp, #{frame}
    stp     x0, x1, [sp, #16 * 0]
    mov     x1, #\kind
    b       trap_entry
.endm

.pushsection .text.vectors, "ax"
.balign 2048
.global exception_vectors
exception_vectors:
    VECTOR 0
    VECTOR 1
    VECTOR 2
    VECTOR 3
    VECTOR 4
    VECTOR 5
    VECTOR 6
    VECTOR 7
    VECTOR 8
    VECTOR 9
    VECTOR 10
    VECTOR 11
    VECTOR 12
    VECTOR 13
    VECTOR 14
    VECTOR 15

trap_entry:                             // x1 = vector index
    stp     x2, x3, [sp, #16 * 1]
    stp     x4, x5, [sp, #16 * 2]
    stp     x6, x7, [sp, #16 * 3]
    stp     x8, x9, [sp, #16 * 4]
    stp     x10, x11, [sp, #16 * 5]
    stp     x12, x13, [sp, #16 * 6]
    stp     x14, x15, [sp, #16 * 7]
    stp     x16, x17, [sp, #16 * 8]
    stp     x18, x19, [sp, #16 * 9]
    stp     x20, x21, [sp, #16 * 10]
    stp     x22, x23, [sp, #16 * 11]
    stp     x24, x25, [sp, #16 * 12]
    stp     x26, x27, [sp, #16 * 13]
    stp     x28, x29, [sp, #16 * 14]
    mrs     x2, sp_el0
    stp     x30, x2, [sp, #16 * 15]
    mrs     x2, elr_el1
    mrs     x3, spsr_el1
    stp     x2, x3, [sp, #16 * 16]
    mov     x0, sp
    bl      trap_dispatch
    ldp     x2, x3, [sp, #16 * 16]
    msr     elr_el1, x2
    msr     spsr_el1, x3
    ldp     x30, x2, [sp, #16 * 15]
    msr     sp_el0, x2
    ldp     x28, x29, [sp, #16 * 14]
    ldp     x26, x27, [sp, #16 * 13]
    ldp     x24, x25, [sp, #16 * 12]
    ldp     x22, x23, [sp, #16 * 11]
    ldp     x20, x21, [sp, #16 * 10]
    ldp     x18, x19, [sp, #16 * 9]
    ldp     x16, x17, [sp, #16 * 8]
    ldp     x14, x15, [sp, #16 * 7]
    ldp     x12, x13, [sp, #16 * 6]
    ldp     x10, x11, [sp, #16 * 5]
    ldp     x8, x9, [sp, #16 * 4]
    ldp     x6, x7, [sp, #16 * 3]
    ldp     x4, x5, [sp, #16 * 2]
    ldp     x2, x3, [sp, #16 * 1]
    ldp     x0, x1, [sp, #16 * 0]
    add     sp, sp, #{frame}
    eret
.popsection
"#,
    frame = const size_of::<TrapFrame>(),
);

const VECTOR_NAMES: [&str; 16] = [
    "EL1t sync",
    "EL1t IRQ",
    "EL1t FIQ",
    "EL1t SError",
    "EL1h sync",
    "EL1h IRQ",
    "EL1h FIQ",
    "EL1h SError",
    "EL0 sync",
    "EL0 IRQ",
    "EL0 FIQ",
    "EL0 SError",
    "EL0/AArch32 sync",
    "EL0/AArch32 IRQ",
    "EL0/AArch32 FIQ",
    "EL0/AArch32 SError",
];
const EL1H_SYNC: u64 = 4;

/// Exception classes (ESR_ELx.EC).
pub mod ec {
    pub const UNKNOWN: u64 = 0x00;
    pub const SVC64: u64 = 0x15;
    pub const IABT_LOWER: u64 = 0x20;
    pub const IABT_CURRENT: u64 = 0x21;
    pub const PC_ALIGNMENT: u64 = 0x22;
    pub const DABT_LOWER: u64 = 0x24;
    pub const DABT_CURRENT: u64 = 0x25;
    pub const SP_ALIGNMENT: u64 = 0x26;
    pub const SERROR: u64 = 0x2f;
    pub const BRK64: u64 = 0x3c;
}

pub const fn exception_class(esr: u64) -> u64 {
    (esr >> 26) & 0x3f
}

fn class_name(esr: u64) -> &'static str {
    match exception_class(esr) {
        ec::UNKNOWN => "unknown/undefined instruction",
        ec::SVC64 => "SVC",
        ec::IABT_LOWER | ec::IABT_CURRENT => "instruction abort",
        ec::PC_ALIGNMENT => "PC alignment fault",
        ec::DABT_LOWER | ec::DABT_CURRENT => "data abort",
        ec::SP_ALIGNMENT => "SP alignment fault",
        ec::SERROR => "SError",
        ec::BRK64 => "BRK",
        _ => "other",
    }
}

#[unsafe(no_mangle)]
extern "C" fn trap_dispatch(frame: &mut TrapFrame, vector: u64) {
    let esr = cpu::esr_el1();
    let far = cpu::far_el1();
    if vector == EL1H_SYNC && probe::fixup(frame, esr, far) {
        return;
    }
    panic!(
        "unhandled exception ({}): {} ESR={esr:#x} FAR={far:#x} ELR={:#x} SPSR={:#x} SP_EL0={:#x}",
        VECTOR_NAMES[(vector & 15) as usize],
        class_name(esr),
        frame.elr,
        frame.spsr,
        frame.sp_el0,
    );
}

#[cfg(feature = "ktest")]
mod tests {
    use super::*;

    ktest! {
        fn brk_traps_and_resumes() {
            let fault = probe::brk();
            kassert_eq!(fault.class(), ec::BRK64);
            kassert_eq!(fault.esr & 0xffff, 0x42);
        }

        fn data_abort_reports_the_faulting_address() {
            let addr = 0xffff_9000_0000_0008;
            // SAFETY: nothing is mapped at `addr`; the probe turns the fault into an error.
            let fault = kunwrap_err!(unsafe { probe::read_u64(addr) });
            kassert_eq!(fault.class(), ec::DABT_CURRENT);
            kassert_eq!(fault.far, addr as u64);
        }
    }
}
