//! Stage-1 translation tables: 4 KiB granule, 48-bit VA, four levels (L0–L3). Tables are
//! identified by physical address and accessed through the linear map.

use super::frame::FrameAllocator;
use super::phys_to_virt;
use crate::arch::mmu::{
    self, ADDR_MASK, AF, AP_EL0, AP_RO, DESC_BLOCK, DESC_PAGE, DESC_TABLE, DESC_VALID, MAIR_DEVICE, MAIR_NORMAL, NG,
    PXN, SH_INNER, UXN, attr_index,
};

pub const PAGE_SIZE: usize = 4096;
pub const BLOCK_2M: usize = 2 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageSize {
    Page4K,
    Block2M,
}

impl PageSize {
    pub const fn bytes(self) -> usize {
        match self {
            PageSize::Page4K => PAGE_SIZE,
            PageSize::Block2M => BLOCK_2M,
        }
    }

    const fn leaf_level(self) -> usize {
        match self {
            PageSize::Page4K => 3,
            PageSize::Block2M => 2,
        }
    }
}

/// Leaf descriptor attributes. Kernel mappings are global and inaccessible from EL0; user
/// mappings are ASID-tagged (nG) and never executable at EL1. With SCTLR_EL1.WXN no
/// mapping is both writable and executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attrs(u64);

impl Attrs {
    pub const KERNEL_RX: Attrs = Attrs(attr_index(MAIR_NORMAL) | SH_INNER | AP_RO | UXN);
    pub const KERNEL_RO: Attrs = Attrs(attr_index(MAIR_NORMAL) | SH_INNER | AP_RO | PXN | UXN);
    pub const KERNEL_RW: Attrs = Attrs(attr_index(MAIR_NORMAL) | SH_INNER | PXN | UXN);
    pub const DEVICE_RW: Attrs = Attrs(attr_index(MAIR_DEVICE) | PXN | UXN);
    pub const USER_RX: Attrs = Attrs(attr_index(MAIR_NORMAL) | SH_INNER | AP_EL0 | AP_RO | NG | PXN);
    pub const USER_RO: Attrs = Attrs(attr_index(MAIR_NORMAL) | SH_INNER | AP_EL0 | AP_RO | NG | PXN | UXN);
    pub const USER_RW: Attrs = Attrs(attr_index(MAIR_NORMAL) | SH_INNER | AP_EL0 | NG | PXN | UXN);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    NonCanonical,
    PhysOutOfRange,
    Misaligned,
    AlreadyMapped,
    NotMapped,
    /// A block mapping covers the address at a higher level.
    BlockInTheWay,
    OutOfMemory,
}

const fn index(va: usize, level: usize) -> usize {
    (va >> (39 - 9 * level)) & 511
}

fn entry(table: usize, index: usize) -> *mut u64 {
    (phys_to_virt(table) as *mut u64).wrapping_add(index)
}

fn read(entry: *mut u64) -> u64 {
    // SAFETY: `entry` points into a translation table reachable through the linear map.
    unsafe { entry.read_volatile() }
}

fn write(entry: *mut u64, value: u64) {
    // SAFETY: as for `read`; callers keep the tables consistent.
    unsafe { entry.write_volatile(value) }
}

fn is_canonical(va: usize) -> bool {
    matches!(va >> 48, 0 | 0xffff)
}

/// Maps `[va, va + size)` to `[pa, pa + size)`, allocating intermediate tables as needed.
pub fn map(
    root: usize,
    va: usize,
    pa: usize,
    size: PageSize,
    attrs: Attrs,
    frames: &mut FrameAllocator,
) -> Result<(), MapError> {
    if !is_canonical(va) {
        return Err(MapError::NonCanonical);
    }
    if pa >> 48 != 0 {
        return Err(MapError::PhysOutOfRange);
    }
    if !(va | pa).is_multiple_of(size.bytes()) {
        return Err(MapError::Misaligned);
    }
    let leaf = size.leaf_level();
    let mut table = root;
    for level in 0..leaf {
        let e = entry(table, index(va, level));
        let d = read(e);
        table = if d & DESC_VALID == 0 {
            let next = frames.alloc().ok_or(MapError::OutOfMemory)?;
            write(e, next as u64 | DESC_TABLE | DESC_VALID);
            next
        } else if d & DESC_TABLE == 0 {
            return Err(MapError::BlockInTheWay);
        } else {
            (d & ADDR_MASK) as usize
        };
    }
    let e = entry(table, index(va, leaf));
    if read(e) & DESC_VALID != 0 {
        return Err(MapError::AlreadyMapped);
    }
    let kind = if leaf == 3 { DESC_PAGE } else { DESC_BLOCK };
    write(e, pa as u64 | attrs.0 | AF | kind | DESC_VALID);
    mmu::sync_tables();
    Ok(())
}

/// The leaf entry mapping `va` and its level.
fn lookup(root: usize, va: usize) -> Result<(*mut u64, usize), MapError> {
    if !is_canonical(va) {
        return Err(MapError::NonCanonical);
    }
    let mut table = root;
    for level in 0..=3 {
        let e = entry(table, index(va, level));
        let d = read(e);
        if d & DESC_VALID == 0 {
            return Err(MapError::NotMapped);
        }
        if level == 3 || d & DESC_TABLE == 0 {
            return Ok((e, level));
        }
        table = (d & ADDR_MASK) as usize;
    }
    unreachable!()
}

/// The physical address `va` maps to, and the leaf descriptor.
pub fn translate(root: usize, va: usize) -> Option<(usize, u64)> {
    let (e, level) = lookup(root, va).ok()?;
    let d = read(e);
    let size = 1usize << (12 + 9 * (3 - level));
    Some((((d & ADDR_MASK) as usize & !(size - 1)) | (va & (size - 1)), d))
}

/// Removes a 4 KiB mapping and returns the frame it mapped. Intermediate tables stay.
pub fn unmap(root: usize, va: usize) -> Result<usize, MapError> {
    let (e, level) = lookup(root, va)?;
    if level != 3 {
        return Err(MapError::BlockInTheWay);
    }
    let d = read(e);
    write(e, 0);
    mmu::flush_tlb_page(va);
    Ok((d & ADDR_MASK) as usize)
}

#[cfg(feature = "ktest")]
mod tests {
    use super::*;
    use crate::arch::exception::ec;
    use crate::arch::probe;
    use crate::mm::{self, layout, virt_to_phys};

    core::arch::global_asm!(
        ".pushsection .text.ktest_ret, \"ax\"",
        ".global aos_ktest_ret",
        "aos_ktest_ret:",
        "    ret",
        ".popsection",
    );

    unsafe extern "C" {
        static aos_ktest_ret: u8;
    }

    const RET: u32 = 0xd65f_03c0;
    static RET_IN_RODATA: u32 = RET;
    static RET_IN_DATA: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(RET);

    /// Unused part of the TTBR1 half (L0 index 256).
    const TEST_VA: usize = 0xffff_8000_0000_0000;

    fn root() -> usize {
        mm::kernel_root()
    }

    ktest! {
        fn kernel_image_has_wx_separated_permissions() {
            let text = &raw const aos_ktest_ret as usize;
            let rodata = &raw const RET_IN_RODATA as usize;
            let data = &raw const RET_IN_DATA as usize;
            for (va, writable, executable) in [(text, false, true), (rodata, false, false), (data, true, false)] {
                let (pa, d) = kunwrap!(translate(root(), va).ok_or("unmapped"));
                kassert_eq!(pa, virt_to_phys(va));
                kassert_eq!(d & AP_RO == 0, writable);
                kassert_eq!(d & PXN == 0, executable);
                kassert!(d & UXN != 0);
            }
        }

        fn text_and_rodata_reject_writes() {
            for va in [&raw const aos_ktest_ret as usize, &raw const RET_IN_RODATA as usize] {
                let va = va & !7;
                // SAFETY: normal memory in the kernel image; the write stores back what was read.
                let value = kunwrap!(unsafe { probe::read_u64(va) });
                let fault = kunwrap_err!(unsafe { probe::write_u64(va, value) });
                kassert_eq!(fault.class(), ec::DABT_CURRENT);
                kassert!(fault.is_permission_fault(3), "ESR {:#x}", fault.esr);
            }
        }

        fn only_text_is_executable() {
            // SAFETY: each target is a lone `ret`.
            kunwrap!(unsafe { probe::call(&raw const aos_ktest_ret as usize) });
            for va in [&raw const RET_IN_RODATA as usize, &raw const RET_IN_DATA as usize] {
                let fault = kunwrap_err!(unsafe { probe::call(va) });
                kassert_eq!(fault.class(), ec::IABT_CURRENT);
                kassert!(fault.is_permission_fault(3), "ESR {:#x}", fault.esr);
            }
            // A `ret` written into a freshly allocated frame of the linear map.
            let pa = kunwrap!(mm::with_frames(|f| f.alloc()).ok_or("out of frames"));
            // SAFETY: the frame is ours and mapped read-write through the linear map.
            unsafe { (phys_to_virt(pa) as *mut u32).write_volatile(RET) };
            let fault = kunwrap_err!(unsafe { probe::call(phys_to_virt(pa)) });
            kassert_eq!(fault.class(), ec::IABT_CURRENT);
        }

        fn identity_map_and_stack_guard_are_unmapped() {
            let image_pa = virt_to_phys(layout::kernel_layout().image.start);
            // SAFETY: probing addresses that must not be mapped.
            let fault = kunwrap_err!(unsafe { probe::read_u64(image_pa) });
            // TTBR0 holds whichever user address space ran last, so the walk may end at any level.
            kassert!((0..4).any(|l| fault.is_translation_fault(l)), "low half: ESR {:#x}", fault.esr);
            let guard = layout::kernel_layout().stack_guard.start;
            let fault = kunwrap_err!(unsafe { probe::read_u64(guard) });
            kassert!(fault.is_translation_fault(3), "stack guard: ESR {:#x}", fault.esr);
        }

        fn map_translate_unmap() {
            let pa = kunwrap!(mm::with_frames(|f| f.alloc()).ok_or("out of frames"));
            kunwrap!(mm::with_frames(|f| map(root(), TEST_VA, pa, PageSize::Page4K, Attrs::KERNEL_RW, f)));
            kassert_eq!(translate(root(), TEST_VA + 0x18).map(|(p, _)| p), Some(pa + 0x18));
            // SAFETY: TEST_VA now maps the frame read-write; the linear map aliases it.
            unsafe { (TEST_VA as *mut u64).write_volatile(0x05a5_a5a5) };
            kassert_eq!(unsafe { (phys_to_virt(pa) as *const u64).read_volatile() }, 0x05a5_a5a5);

            kassert_eq!(mm::with_frames(|f| map(root(), TEST_VA, pa, PageSize::Page4K, Attrs::KERNEL_RW, f)), Err(MapError::AlreadyMapped));
            kassert_eq!(mm::with_frames(|f| map(root(), TEST_VA + 8, pa, PageSize::Page4K, Attrs::KERNEL_RW, f)), Err(MapError::Misaligned));
            kassert_eq!(mm::with_frames(|f| map(root(), 0x0001_0000_0000_0000, pa, PageSize::Page4K, Attrs::KERNEL_RW, f)), Err(MapError::NonCanonical));

            kassert_eq!(unmap(root(), TEST_VA), Ok(pa));
            kassert_eq!(translate(root(), TEST_VA), None);
            kassert_eq!(unmap(root(), TEST_VA), Err(MapError::NotMapped));
            // SAFETY: probing an address that was just unmapped.
            let fault = kunwrap_err!(unsafe { probe::read_u64(TEST_VA) });
            kassert!(fault.is_translation_fault(3), "ESR {:#x}", fault.esr);
        }

        fn linear_map_covers_all_ram_with_blocks() {
            for r in crate::boot_info().platform.memory.as_slice() {
                let last = r.end - 8;
                let (pa, d) = kunwrap!(translate(root(), phys_to_virt(last)).ok_or("end of RAM unmapped"));
                kassert_eq!(pa, last);
                kassert_eq!(d & DESC_TABLE, DESC_BLOCK, "expected a 2 MiB block at the end of RAM");
                kassert!(d & PXN != 0 && d & AP_RO == 0);
                kassert_eq!(unmap(root(), phys_to_virt(last)), Err(MapError::BlockInTheWay));
            }
        }

        fn uart_is_mapped_as_device_memory() {
            let uart = kunwrap!(crate::boot_info().platform.uart.ok_or("no uart"));
            let (_, d) = kunwrap!(translate(root(), phys_to_virt(uart)).ok_or("uart unmapped"));
            kassert_eq!((d >> 2) & 7, MAIR_DEVICE);
            kassert!(d & PXN != 0 && d & UXN != 0);
        }
    }
}
