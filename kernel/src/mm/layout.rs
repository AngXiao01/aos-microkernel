//! Kernel image layout, from the symbols in `link.ld`. All addresses are virtual.

use super::region::Region;

unsafe extern "C" {
    static __kernel_start: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __stack_guard_start: u8;
    static __stack_guard_end: u8;
    static __kernel_end: u8;
}

pub struct KernelLayout {
    pub image: Region,
    pub text: Region,
    pub rodata: Region,
    /// Unmapped page below the boot stack.
    pub stack_guard: Region,
}

pub fn kernel_layout() -> KernelLayout {
    let addr = |p: *const u8| p as usize;
    KernelLayout {
        image: Region::new(addr(&raw const __kernel_start), addr(&raw const __kernel_end)),
        text: Region::new(addr(&raw const __text_start), addr(&raw const __text_end)),
        rodata: Region::new(addr(&raw const __rodata_start), addr(&raw const __rodata_end)),
        stack_guard: Region::new(addr(&raw const __stack_guard_start), addr(&raw const __stack_guard_end)),
    }
}
