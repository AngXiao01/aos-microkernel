/*
 * AOS kernel image. Linked inside the TTBR1 linear map (VA = PA + KERNEL_VA_BASE) and
 * loaded at KERNEL_LOAD_PA: QEMU's -kernel loads each PT_LOAD segment at its LMA and
 * enters at the physical entry point _start_pa with the MMU off.
 *
 * Section boundaries are page-aligned so the kernel can map text RX, rodata R and
 * data/bss/stack RW+XN (W^X), with an unmapped guard page below the boot stack.
 */
OUTPUT_ARCH(aarch64)
ENTRY(_start_pa)

KERNEL_VA_BASE = 0xFFFF000000000000;
KERNEL_LOAD_PA = 0x40200000;

SECTIONS
{
    . = KERNEL_VA_BASE + KERNEL_LOAD_PA;
    __kernel_start = .;

    .text : AT(ADDR(.text) - KERNEL_VA_BASE) {
        __text_start = .;
        KEEP(*(.text.boot))
        *(.text .text.*)
    }
    . = ALIGN(4096);
    __text_end = .;

    .rodata : AT(ADDR(.rodata) - KERNEL_VA_BASE) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
        . = ALIGN(8);
        __ktest_start = .;
        KEEP(*(.ktest_array))
        __ktest_end = .;
    }
    . = ALIGN(4096);
    __rodata_end = .;

    .data : AT(ADDR(.data) - KERNEL_VA_BASE) {
        __data_start = .;
        *(.data .data.*)
        *(.got .got.*)
    }

    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_VA_BASE) {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    . = ALIGN(4096);
    __stack_guard_start = .;
    . += 4096;
    __stack_guard_end = .;
    . += 0x10000;
    __boot_stack_top = .;
    __kernel_end = .;

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame .eh_frame_hdr) }
}

_start_pa = _start - KERNEL_VA_BASE;
