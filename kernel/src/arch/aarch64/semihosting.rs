//! Semihosting exit, for test builds only: semihosting gives the guest access to host
//! files, so normal boots never use it and QEMU is started without it.

const SYS_EXIT: u64 = 0x18;
const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x20026;

/// Terminates QEMU with `code` as its exit status.
pub fn exit(code: u32) -> ! {
    let block = [ADP_STOPPED_APPLICATION_EXIT, u64::from(code)];
    // SAFETY: SYS_EXIT reads the two-word parameter block and does not return.
    unsafe {
        core::arch::asm!("hlt #0xf000", in("x0") SYS_EXIT, in("x1") block.as_ptr(), options(nostack));
    }
    super::cpu::halt()
}
