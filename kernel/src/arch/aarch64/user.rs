//! Running user threads.
//!
//! [`enter`] saves the kernel's callee-saved registers on the kernel stack, loads a user
//! context and `eret`s to EL0. Any exception from EL0 (system call, fault, interrupt) lands
//! in the EL0 vectors, which store the user registers back into the same context and return
//! from `enter` with the vector index. The kernel is therefore a plain loop around `enter`
//! (`sched::run`) with one kernel stack and no kernel threads.
//!
//! FP/SIMD registers are never touched by the kernel (soft-float target), so they keep the
//! state of whichever thread ran last; [`fp_save`] and [`fp_restore`] switch them.

use super::exception::TrapFrame;

/// Saved general-purpose state of a user thread; the layout is shared with the vectors.
pub type UserContext = TrapFrame;

/// SPSR for a fresh user thread: EL0t, all interrupts unmasked.
pub const SPSR_EL0: u64 = 0;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FpState {
    pub q: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

impl FpState {
    pub const ZERO: FpState = FpState { q: [0; 32], fpcr: 0, fpsr: 0 };
}

core::arch::global_asm!(
    r#"
.pushsection .text.user, "ax"
.global aos_enter_user
aos_enter_user:                         // (ctx: *mut UserContext) -> vector index
    sub     sp, sp, #96
    stp     x19, x20, [sp, #0]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    msr     tpidr_el1, x0               // the EL0 vectors save into this context
    ldp     x9, x10, [x0, #256]
    msr     elr_el1, x9
    msr     spsr_el1, x10
    ldr     x9, [x0, #248]
    msr     sp_el0, x9
    ldp     x2, x3, [x0, #16 * 1]
    ldp     x4, x5, [x0, #16 * 2]
    ldp     x6, x7, [x0, #16 * 3]
    ldp     x8, x9, [x0, #16 * 4]
    ldp     x10, x11, [x0, #16 * 5]
    ldp     x12, x13, [x0, #16 * 6]
    ldp     x14, x15, [x0, #16 * 7]
    ldp     x16, x17, [x0, #16 * 8]
    ldp     x18, x19, [x0, #16 * 9]
    ldp     x20, x21, [x0, #16 * 10]
    ldp     x22, x23, [x0, #16 * 11]
    ldp     x24, x25, [x0, #16 * 12]
    ldp     x26, x27, [x0, #16 * 13]
    ldp     x28, x29, [x0, #16 * 14]
    ldr     x30, [x0, #16 * 15]
    ldp     x0, x1, [x0, #0]
    eret

.global aos_user_exit
aos_user_exit:                          // from an EL0 vector: x0 = context, x1 = vector index,
    stp     x2, x3, [x0, #16 * 1]       // user x0/x1 pushed on the kernel stack
    stp     x4, x5, [x0, #16 * 2]
    stp     x6, x7, [x0, #16 * 3]
    stp     x8, x9, [x0, #16 * 4]
    stp     x10, x11, [x0, #16 * 5]
    stp     x12, x13, [x0, #16 * 6]
    stp     x14, x15, [x0, #16 * 7]
    stp     x16, x17, [x0, #16 * 8]
    stp     x18, x19, [x0, #16 * 9]
    stp     x20, x21, [x0, #16 * 10]
    stp     x22, x23, [x0, #16 * 11]
    stp     x24, x25, [x0, #16 * 12]
    stp     x26, x27, [x0, #16 * 13]
    stp     x28, x29, [x0, #16 * 14]
    mrs     x2, sp_el0
    stp     x30, x2, [x0, #16 * 15]
    mrs     x2, elr_el1
    mrs     x3, spsr_el1
    stp     x2, x3, [x0, #16 * 16]
    ldp     x2, x3, [sp], #16
    stp     x2, x3, [x0, #0]
    mov     x0, x1
    ldp     x19, x20, [sp, #0]
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    ldp     x29, x30, [sp, #80]
    add     sp, sp, #96
    ret

.arch_extension fp
.arch_extension simd
.global aos_fp_save
aos_fp_save:                            // (state: *mut FpState)
    stp     q0, q1, [x0, #32 * 0]
    stp     q2, q3, [x0, #32 * 1]
    stp     q4, q5, [x0, #32 * 2]
    stp     q6, q7, [x0, #32 * 3]
    stp     q8, q9, [x0, #32 * 4]
    stp     q10, q11, [x0, #32 * 5]
    stp     q12, q13, [x0, #32 * 6]
    stp     q14, q15, [x0, #32 * 7]
    stp     q16, q17, [x0, #32 * 8]
    stp     q18, q19, [x0, #32 * 9]
    stp     q20, q21, [x0, #32 * 10]
    stp     q22, q23, [x0, #32 * 11]
    stp     q24, q25, [x0, #32 * 12]
    stp     q26, q27, [x0, #32 * 13]
    stp     q28, q29, [x0, #32 * 14]
    stp     q30, q31, [x0, #32 * 15]
    mrs     x1, fpcr
    mrs     x2, fpsr
    add     x3, x0, #512                // beyond stp's immediate range
    stp     x1, x2, [x3]
    ret

.global aos_fp_restore
aos_fp_restore:                         // (state: *const FpState)
    ldp     q0, q1, [x0, #32 * 0]
    ldp     q2, q3, [x0, #32 * 1]
    ldp     q4, q5, [x0, #32 * 2]
    ldp     q6, q7, [x0, #32 * 3]
    ldp     q8, q9, [x0, #32 * 4]
    ldp     q10, q11, [x0, #32 * 5]
    ldp     q12, q13, [x0, #32 * 6]
    ldp     q14, q15, [x0, #32 * 7]
    ldp     q16, q17, [x0, #32 * 8]
    ldp     q18, q19, [x0, #32 * 9]
    ldp     q20, q21, [x0, #32 * 10]
    ldp     q22, q23, [x0, #32 * 11]
    ldp     q24, q25, [x0, #32 * 12]
    ldp     q26, q27, [x0, #32 * 13]
    ldp     q28, q29, [x0, #32 * 14]
    ldp     q30, q31, [x0, #32 * 15]
    add     x3, x0, #512
    ldp     x1, x2, [x3]
    msr     fpcr, x1
    msr     fpsr, x2
    ret
.popsection
"#
);

const _: () = assert!(core::mem::offset_of!(FpState, fpcr) == 512);

unsafe extern "C" {
    fn aos_enter_user(ctx: *mut UserContext) -> u64;
    fn aos_fp_save(state: *mut FpState);
    fn aos_fp_restore(state: *const FpState);
}

/// Runs the user context until it takes an exception; returns the vector index (8–15).
///
/// # Safety
/// `ctx` must describe valid EL0 state (SPSR selecting EL0, a mapped user address space in
/// TTBR0) and stay valid and otherwise unaliased until this returns.
pub unsafe fn enter(ctx: *mut UserContext) -> u64 {
    // SAFETY: guaranteed by the caller.
    unsafe { aos_enter_user(ctx) }
}

pub fn fp_save(state: &mut FpState) {
    // SAFETY: writes exactly one FpState; CPACR_EL1 allows FP/SIMD access at EL1.
    unsafe { aos_fp_save(state) }
}

pub fn fp_restore(state: &FpState) {
    // SAFETY: reads exactly one FpState.
    unsafe { aos_fp_restore(state) }
}

/// Lets a pending interrupt be taken at EL1 while idle: the interrupt wakes `wfi` even
/// while masked, is taken in the short unmasked window, and is handled by the EL1 vector.
pub fn wait_for_interrupt() {
    // SAFETY: only changes the IRQ mask, restored before returning.
    unsafe { core::arch::asm!("wfi", "msr daifclr, #2", "isb", "msr daifset, #2", options(nostack)) };
}
