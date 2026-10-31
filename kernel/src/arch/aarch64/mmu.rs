//! Stage-1 translation constants and maintenance (Arm ARM D8): 4 KiB granule, 48-bit VA.

use core::arch::asm;

// Descriptor bits.
pub const DESC_VALID: u64 = 1 << 0;
/// Table descriptor at L0–L2; page descriptor at L3.
pub const DESC_TABLE: u64 = 1 << 1;
pub const DESC_PAGE: u64 = 1 << 1;
pub const DESC_BLOCK: u64 = 0;
pub const AP_EL0: u64 = 1 << 6;
pub const AP_RO: u64 = 1 << 7;
pub const SH_INNER: u64 = 3 << 8;
pub const AF: u64 = 1 << 10;
/// Not global: the TLB entry is tagged with the ASID (user mappings).
pub const NG: u64 = 1 << 11;
pub const PXN: u64 = 1 << 53;
pub const UXN: u64 = 1 << 54;
pub const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

pub const fn attr_index(index: u64) -> u64 {
    index << 2
}

/// MAIR_EL1 attribute indices.
pub const MAIR_DEVICE: u64 = 0; // Device-nGnRE
pub const MAIR_NORMAL: u64 = 1; // Normal, inner/outer write-back, read/write-allocate
pub const MAIR_VALUE: u64 = 0x04 | (0xff << 8);

/// TCR_EL1 without IPS (boot code fills it in from ID_AA64MMFR0_EL1.PARange):
/// T0SZ = T1SZ = 16 (48-bit), 4 KiB granules (TG0 = 0b00, TG1 = 0b10), inner-shareable
/// write-back write-allocate table walks for both halves.
pub const TCR_VALUE: u64 = 16 | (1 << 8) | (1 << 10) | (3 << 12) // T0SZ, IRGN0, ORGN0, SH0
    | (16 << 16) | (1 << 24) | (1 << 26) | (3 << 28) | (2 << 30); // T1SZ, IRGN1, ORGN1, SH1, TG1

/// SCTLR_EL1 RES1 bits (ARMv8.0 encoding of bits 11, 20, 22, 23, 28, 29).
const SCTLR_RES1: u64 = (1 << 11) | (1 << 20) | (1 << 22) | (1 << 23) | (1 << 28) | (1 << 29);
/// MMU, data and instruction caches, SP alignment checks at EL1 and EL0.
pub const SCTLR_BOOT: u64 = SCTLR_RES1 | (1 << 0) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 12);
/// Writable implies execute-never.
pub const SCTLR_WXN: u64 = 1 << 19;

/// Makes page-table writes visible to the table walker.
pub fn sync_tables() {
    // SAFETY: barriers only.
    unsafe { asm!("dsb ishst", "isb", options(nostack, preserves_flags)) };
}

/// Makes `ttbr0 | asid << 48` the user address space. Entries are ASID-tagged, so no TLB
/// maintenance is needed.
pub fn set_user_space(ttbr0: usize, asid: u16) {
    let value = ttbr0 as u64 | (u64::from(asid) << 48);
    // SAFETY: the kernel runs from TTBR1 only; TTBR0 changes what EL0 sees.
    unsafe { asm!("msr ttbr0_el1, {}", "isb", in(reg) value, options(nostack, preserves_flags)) };
}

/// Invalidates the TLB entries for `va` in all ASIDs.
pub fn flush_tlb_page(va: usize) {
    let operand = (va >> 12) & ((1 << 44) - 1);
    // SAFETY: TLB maintenance only removes cached translations.
    unsafe {
        asm!("dsb ishst", "tlbi vaae1is, {}", "dsb ish", "isb", in(reg) operand, options(nostack, preserves_flags))
    };
}

/// Installs new translation tables and drops all cached translations.
///
/// # Safety
/// `ttbr1` must map everything the kernel touches from here on at the same virtual
/// addresses as the current tables; `ttbr0` must be a valid (possibly empty) table.
pub unsafe fn switch_tables(ttbr1: usize, ttbr0: usize) {
    // QEMU does not model TLB conflict aborts, so no break-before-make dance (§B2: QEMU only).
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!(
            "dsb ishst",
            "msr ttbr1_el1, {ttbr1}",
            "msr ttbr0_el1, {ttbr0}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            ttbr1 = in(reg) ttbr1,
            ttbr0 = in(reg) ttbr0,
            options(nostack, preserves_flags),
        )
    };
}

/// Turns on SCTLR_EL1.WXN.
///
/// # Safety
/// No code may still be executing from a writable mapping.
pub unsafe fn enable_wxn() {
    let sctlr = super::cpu::sctlr_el1() | SCTLR_WXN;
    // SAFETY: guaranteed by the caller; WXN may be cached in TLB entries, hence the flush.
    unsafe {
        asm!(
            "msr sctlr_el1, {}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            in(reg) sctlr,
            options(nostack, preserves_flags),
        )
    };
}
