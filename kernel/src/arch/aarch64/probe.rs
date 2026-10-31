//! Fault-tolerant probes: a read, write, `brk` or call that faults returns the exception
//! syndrome instead of panicking. The exception handler recognises the probe by the
//! faulting instruction's address ([`fixup`]). The kernel tests use this to check page
//! permissions; copying IPC buffers from user memory (B-1) needs the same mechanism.

use core::sync::atomic::{AtomicU64, Ordering};

use super::exception::{TrapFrame, ec, exception_class};

core::arch::global_asm!(
    r#"
.pushsection .text.probe, "ax"
.global aos_probe_read_u64
aos_probe_read_u64:                     // (addr) -> (value, esr)
    mov     x1, xzr
.global aos_probe_read_insn
aos_probe_read_insn:
    ldr     x0, [x0]
    ret

.global aos_probe_write_u64
aos_probe_write_u64:                    // (addr, value) -> (_, esr)
    mov     x2, x1
    mov     x1, xzr
.global aos_probe_write_insn
aos_probe_write_insn:
    str     x2, [x0]
    ret

.global aos_probe_brk
aos_probe_brk:                          // () -> (_, esr)
    mov     x1, xzr
.global aos_probe_brk_insn
aos_probe_brk_insn:
    brk     #0x42
    ret

.global aos_probe_call
aos_probe_call:                         // (target) -> (_, esr)
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    mov     x1, xzr
    blr     x0
.global aos_probe_call_return
aos_probe_call_return:
    ldp     x29, x30, [sp], #16
    ret
.popsection
"#
);

#[repr(C)]
struct Raw {
    value: u64,
    esr: u64,
}

unsafe extern "C" {
    fn aos_probe_read_u64(addr: usize) -> Raw;
    fn aos_probe_write_u64(addr: usize, value: u64) -> Raw;
    fn aos_probe_brk() -> Raw;
    fn aos_probe_call(target: usize) -> Raw;
    static aos_probe_read_insn: u8;
    static aos_probe_write_insn: u8;
    static aos_probe_brk_insn: u8;
    static aos_probe_call_return: u8;
}

/// FAR of the last probe fault (single core: probes do not nest).
static LAST_FAR: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub esr: u64,
    pub far: u64,
}

impl Fault {
    pub fn class(&self) -> u64 {
        exception_class(self.esr)
    }

    /// Data/instruction fault status code (ESR.ISS[5:0]).
    pub fn status(&self) -> u64 {
        self.esr & 0x3f
    }

    pub fn is_translation_fault(&self, level: u64) -> bool {
        self.status() == 0b00_0100 | level
    }

    pub fn is_permission_fault(&self, level: u64) -> bool {
        self.status() == 0b00_1100 | level
    }
}

fn result(raw: Raw) -> Result<u64, Fault> {
    match raw.esr {
        0 => Ok(raw.value),
        esr => Err(Fault { esr, far: LAST_FAR.load(Ordering::Relaxed) }),
    }
}

/// # Safety
/// Reading `addr`, if it is mapped, must have no side effects (no device registers).
pub unsafe fn read_u64(addr: usize) -> Result<u64, Fault> {
    // SAFETY: guaranteed by the caller; faults are recovered by `fixup`.
    result(unsafe { aos_probe_read_u64(addr) })
}

/// # Safety
/// If `addr` is writable, writing `value` there must not break any invariant.
pub unsafe fn write_u64(addr: usize, value: u64) -> Result<(), Fault> {
    // SAFETY: guaranteed by the caller; faults are recovered by `fixup`.
    result(unsafe { aos_probe_write_u64(addr, value) }).map(|_| ())
}

/// Executes `brk #0x42` and returns the resulting fault.
pub fn brk() -> Fault {
    // SAFETY: the brk instruction is recovered by `fixup`.
    match result(unsafe { aos_probe_brk() }) {
        Err(fault) => fault,
        Ok(_) => panic!("brk did not trap"),
    }
}

/// Branches to `target`.
///
/// # Safety
/// If `target` is executable, it must return immediately with x1 unchanged (a lone `ret`).
pub unsafe fn call(target: usize) -> Result<(), Fault> {
    // SAFETY: guaranteed by the caller; an instruction abort at `target` is recovered by `fixup`.
    result(unsafe { aos_probe_call(target) }).map(|_| ())
}

/// Recovers from a fault raised by a probe: resumes after the probe instruction (or at the
/// call's return address) with x1 = ESR. Returns false if the fault is not a probe's.
pub(super) fn fixup(frame: &mut TrapFrame, esr: u64, far: u64) -> bool {
    let elr = frame.elr as usize;
    let call_return = &raw const aos_probe_call_return as usize;
    let resume = if elr == &raw const aos_probe_read_insn as usize
        || elr == &raw const aos_probe_write_insn as usize
        || elr == &raw const aos_probe_brk_insn as usize
    {
        elr + 4
    } else if exception_class(esr) == ec::IABT_CURRENT && frame.x[30] as usize == call_return {
        call_return
    } else {
        return false;
    };
    LAST_FAR.store(far, Ordering::Relaxed);
    frame.x[1] = esr;
    frame.elr = resume as u64;
    true
}
