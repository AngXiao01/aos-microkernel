/* User programs: linked at USER_MIN (aos-abi layout), one PT_LOAD segment per
 * permission, each page-aligned so the kernel can map them W^X. */
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);   /* R X */
    rodata PT_LOAD FLAGS(4); /* R */
    data PT_LOAD FLAGS(6);   /* R W */
}

SECTIONS
{
    . = 0x400000;
    .text : { KEEP(*(.text._start)) *(.text .text.*) } :text
    . = ALIGN(4096);
    .rodata : { *(.rodata .rodata.*) *(.data.rel.ro .data.rel.ro.*) } :rodata
    . = ALIGN(4096);
    .data : { *(.data .data.*) *(.got .got.*) } :data
    .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame .eh_frame_hdr) }
}
