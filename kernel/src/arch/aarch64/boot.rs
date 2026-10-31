//! Kernel entry. Runs at the physical load address with the MMU off.
//!
//! 1. Only CPU 0 continues (v1 is single-core, §B3.1). Entry at EL2 drops to EL1.
//! 2. Zero .bss. `adrp` is PC-relative and VMA - LMA is the same for every section, so
//!    symbol addresses computed here are physical.
//! 3. Build the boot translation table: one L0 and one L1 table shared by TTBR0 and TTBR1,
//!    so PA [0, 4 GiB) is mapped both at identity and at `PA + PHYS_OFFSET`. L1[0] (devices)
//!    is Device-nGnRE, L1[1..4] (RAM) is Normal write-back.
//! 4. Enable the MMU, jump to the linked (high) address, set up the stack and the exception
//!    vectors, and call `kernel_main(dtb)`. `mm::init` then replaces the boot table.
//!
//! QEMU does not model caches, so no cache maintenance is done (§B2: QEMU only).

use core::sync::atomic::{AtomicU64, Ordering};

use super::mmu;

/// Exception level the kernel was entered at (1 or 2), written by the boot code.
static ENTRY_EL: AtomicU64 = AtomicU64::new(0);

pub fn entry_el() -> u64 {
    ENTRY_EL.load(Ordering::Relaxed)
}

/// Number of 1 GiB blocks in the boot map.
const BOOT_MAP_GIB: u64 = 4;

const BOOT_DEVICE_BLOCK: u64 =
    mmu::DESC_VALID | mmu::DESC_BLOCK | mmu::attr_index(mmu::MAIR_DEVICE) | mmu::AF | mmu::PXN | mmu::UXN;
const BOOT_NORMAL_BLOCK: u64 =
    mmu::DESC_VALID | mmu::DESC_BLOCK | mmu::attr_index(mmu::MAIR_NORMAL) | mmu::SH_INNER | mmu::AF | mmu::UXN;

core::arch::global_asm!(
    r#"
.pushsection .text.boot, "ax"
.global _start
_start:
    mov     x19, x0                     // DTB address if the loader passed one; 0 for a bare ELF boot
    mrs     x1, mpidr_el1
    and     x1, x1, #0xff
    cbnz    x1, .Lpark
    mrs     x20, CurrentEL
    lsr     x20, x20, #2
    cmp     x20, #1
    b.eq    .Lat_el1
    cmp     x20, #2
    b.ne    .Lpark                      // EL3 entry is not supported

    mov     x1, #(1 << 31)              // HCR_EL2.RW: EL1 runs AArch64
    msr     hcr_el2, x1
    mov     x1, #3                      // CNTHCTL_EL2: EL1 may use the physical counter and timer
    msr     cnthctl_el2, x1
    msr     cntvoff_el2, xzr
    mov     x1, #0x3c5                  // SPSR_EL2: D, A, I, F masked; EL1h
    msr     spsr_el2, x1
    adr     x1, .Lat_el1
    msr     elr_el2, x1
    eret

.Lat_el1:
    msr     daifset, #0xf
    mov     x1, #(3 << 20)              // CPACR_EL1.FPEN: no FP/SIMD traps (the kernel itself
    msr     cpacr_el1, x1               // never uses FP; it only saves and restores user state)
    mov     x1, #(1 << 1)               // CNTKCTL_EL1.EL0VCTEN: EL0 may read the virtual counter
    msr     cntkctl_el1, x1
    isb
    adrp    x1, __bss_start
    add     x1, x1, :lo12:__bss_start
    adrp    x2, __bss_end
    add     x2, x2, :lo12:__bss_end
1:  cmp     x1, x2
    b.hs    2f
    str     xzr, [x1], #8
    b       1b
2:  adrp    x1, {entry_el}
    add     x1, x1, :lo12:{entry_el}
    str     x20, [x1]

    adrp    x1, boot_l0
    adrp    x2, boot_l1
    orr     x3, x2, #{table}
    str     x3, [x1]
    ldr     x3, ={device_block}
    str     x3, [x2]
    ldr     x3, ={normal_block}
    mov     x5, #(1 << 30)
    add     x3, x3, x5
    mov     x4, #1
3:  str     x3, [x2, x4, lsl #3]
    add     x3, x3, x5
    add     x4, x4, #1
    cmp     x4, #{boot_gib}
    b.lo    3b

    ldr     x1, ={mair}
    msr     mair_el1, x1
    ldr     x1, ={tcr}
    mrs     x2, id_aa64mmfr0_el1
    and     x2, x2, #0xf
    mov     x3, #5
    cmp     x2, x3
    csel    x2, x2, x3, ls              // IPS = min(PARange, 48 bits)
    bfi     x1, x2, #32, #3
    msr     tcr_el1, x1
    adrp    x1, boot_l0
    msr     ttbr0_el1, x1
    msr     ttbr1_el1, x1
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    ldr     x1, ={sctlr}
    msr     sctlr_el1, x1
    isb
    ldr     x1, =.Lhigh
    br      x1

.Lhigh:
    ldr     x1, =__boot_stack_top
    mov     sp, x1
    ldr     x1, =exception_vectors
    msr     vbar_el1, x1
    isb
    msr     daifclr, #4                 // unmask SError
    mov     x0, x19
    bl      kernel_main
.Lpark:
    wfe
    b       .Lpark
.ltorg

.pushsection .bss.boot_tables, "aw", %nobits
.balign 4096
boot_l0: .space 4096
boot_l1: .space 4096
.popsection
.popsection
"#,
    entry_el = sym ENTRY_EL,
    table = const mmu::DESC_TABLE | mmu::DESC_VALID,
    device_block = const BOOT_DEVICE_BLOCK,
    normal_block = const BOOT_NORMAL_BLOCK,
    boot_gib = const BOOT_MAP_GIB,
    mair = const mmu::MAIR_VALUE,
    tcr = const mmu::TCR_VALUE,
    sctlr = const mmu::SCTLR_BOOT,
);
