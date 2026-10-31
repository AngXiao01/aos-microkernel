//! Memory management (§B3.1): boot frame allocator and the kernel address space.
//!
//! Kernel address space: TTBR1 holds a linear map, `VA = PA + PHYS_OFFSET`, of all RAM and
//! of the devices the kernel uses. The kernel image lives inside it, mapped with per-section
//! permissions (text RX, rodata R, data/bss/stack RW + XN) and an unmapped stack guard page,
//! so no writable alias of kernel code exists. TTBR0 is reserved for user address spaces
//! and points at an empty table until there are any. SCTLR_EL1.WXN is on.

pub mod frame;
pub mod layout;
pub mod paging;
pub mod region;

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::mmu;
use crate::fdt::Platform;
use crate::sync::SpinLock;
use frame::FrameAllocator;
use layout::KernelLayout;
use paging::{Attrs, BLOCK_2M, MapError, PAGE_SIZE, PageSize};
use region::{ListFull, Region, RegionList};

pub const PHYS_OFFSET: usize = 0xffff_0000_0000_0000;
/// The boot map (`arch::boot`) covers PA [0, 4 GiB).
const BOOT_MAP_END: usize = 4 << 30;

pub const fn phys_to_virt(pa: usize) -> usize {
    pa + PHYS_OFFSET
}

/// Only valid for addresses in the linear map.
pub const fn virt_to_phys(va: usize) -> usize {
    va - PHYS_OFFSET
}

static FRAMES: SpinLock<Option<FrameAllocator>> = SpinLock::new(None);
/// Physical address of the TTBR1 root table.
static KERNEL_ROOT: AtomicUsize = AtomicUsize::new(0);

pub enum InitError {
    TooManyRegions,
    Map(MapError),
}

impl core::fmt::Display for InitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InitError::TooManyRegions => f.write_str("too many memory regions"),
            InitError::Map(e) => write!(f, "mapping failed: {e:?}"),
        }
    }
}

impl From<ListFull> for InitError {
    fn from(_: ListFull) -> InitError {
        InitError::TooManyRegions
    }
}

impl From<MapError> for InitError {
    fn from(e: MapError) -> InitError {
        InitError::Map(e)
    }
}

pub struct MmStats {
    pub table_frames: usize,
    pub free_bytes: usize,
}

/// Builds the kernel address space and switches to it. `reserved` lists physical ranges
/// besides the kernel image that must not be allocated (the DTB, its reservation block);
/// `devices` lists the MMIO ranges the kernel itself uses (console, interrupt controller).
pub fn init(platform: &Platform<'_>, reserved: &[Region], devices: &[Region]) -> Result<MmStats, InitError> {
    let layout = layout::kernel_layout();
    let mut all_reserved: RegionList<16> = RegionList::new();
    all_reserved.push(Region::new(virt_to_phys(layout.image.start), virt_to_phys(layout.image.end)))?;
    for r in reserved {
        all_reserved.push(*r)?;
    }
    let mut frames = FrameAllocator::new(platform.memory.as_slice(), all_reserved.as_slice())?;
    frames.set_limit(BOOT_MAP_END);

    let root = build_kernel_space(&layout, platform.memory.as_slice(), devices, &mut frames)?;
    let empty_ttbr0 = frames.alloc().ok_or(MapError::OutOfMemory)?;
    // SAFETY: the new tables map the kernel image, the boot stack, all RAM and the devices
    // at the same virtual addresses as the boot map, and no code runs from a writable page.
    unsafe {
        mmu::switch_tables(root, empty_ttbr0);
        mmu::enable_wxn();
    }
    frames.set_limit(usize::MAX);

    let stats = MmStats { table_frames: frames.allocated(), free_bytes: frames.free_bytes() };
    KERNEL_ROOT.store(root, Ordering::Release);
    *FRAMES.lock() = Some(frames);
    Ok(stats)
}

pub fn kernel_root() -> usize {
    KERNEL_ROOT.load(Ordering::Acquire)
}

/// Runs `f` with the frame allocator. Panics before `init`.
pub fn with_frames<R>(f: impl FnOnce(&mut FrameAllocator) -> R) -> R {
    let mut guard = FRAMES.lock();
    f(guard.as_mut().expect("frame allocator not initialised"))
}

fn build_kernel_space(
    layout: &KernelLayout,
    ram: &[Region],
    devices: &[Region],
    frames: &mut FrameAllocator,
) -> Result<usize, MapError> {
    let root = frames.alloc().ok_or(MapError::OutOfMemory)?;
    let image = Region::new(virt_to_phys(layout.image.start), virt_to_phys(layout.image.end));
    for r in ram {
        let r = r.align_inward(PAGE_SIZE);
        let mut pa = r.start;
        while pa < r.end {
            let block = Region::new(pa, pa + BLOCK_2M);
            if pa % BLOCK_2M == 0 && block.end <= r.end && !block.overlaps(&image) {
                paging::map(root, phys_to_virt(pa), pa, PageSize::Block2M, Attrs::KERNEL_RW, frames)?;
                pa += BLOCK_2M;
            } else {
                if let Some(attrs) = page_attrs(layout, phys_to_virt(pa)) {
                    paging::map(root, phys_to_virt(pa), pa, PageSize::Page4K, attrs, frames)?;
                }
                pa += PAGE_SIZE;
            }
        }
    }
    for d in devices {
        let d = d.align_outward(PAGE_SIZE);
        for pa in (d.start..d.end).step_by(PAGE_SIZE) {
            paging::map(root, phys_to_virt(pa), pa, PageSize::Page4K, Attrs::DEVICE_RW, frames)?;
        }
    }
    Ok(root)
}

/// Permissions for a 4 KiB page of RAM; `None` leaves it unmapped.
fn page_attrs(layout: &KernelLayout, va: usize) -> Option<Attrs> {
    if layout.text.contains(va) {
        Some(Attrs::KERNEL_RX)
    } else if layout.rodata.contains(va) {
        Some(Attrs::KERNEL_RO)
    } else if layout.stack_guard.contains(va) {
        None
    } else {
        Some(Attrs::KERNEL_RW)
    }
}
