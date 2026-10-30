//! Boot-time physical frame allocator: zeroed 4 KiB frames for the kernel's own page
//! tables, handed out from the lowest free address up. Frames are never freed; whatever is
//! left becomes Untyped memory for the root task (B-2).

use super::paging::PAGE_SIZE;
use super::phys_to_virt;
use super::region::{ListFull, Region, RegionList};

pub struct FrameAllocator {
    free: RegionList<32>,
    /// Only frames below this address are handed out (the part of RAM that is mapped).
    limit: usize,
    allocated: usize,
}

impl FrameAllocator {
    /// Free memory = `memory` (shrunk to page boundaries) minus `reserved` (grown to page
    /// boundaries).
    pub fn new(memory: &[Region], reserved: &[Region]) -> Result<FrameAllocator, ListFull> {
        let mut free = RegionList::new();
        for r in memory {
            free.push(r.align_inward(PAGE_SIZE))?;
        }
        for r in reserved {
            free.subtract(r.align_outward(PAGE_SIZE))?;
        }
        free.sort_by_start();
        Ok(FrameAllocator { free, limit: usize::MAX, allocated: 0 })
    }

    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }

    /// A zeroed frame, by physical address.
    pub fn alloc(&mut self) -> Option<usize> {
        let limit = self.limit;
        let region =
            self.free.as_mut_slice().iter_mut().find(|r| r.len() >= PAGE_SIZE && r.start + PAGE_SIZE <= limit)?;
        let pa = region.start;
        region.start += PAGE_SIZE;
        self.allocated += 1;
        // SAFETY: `pa` is free RAM below `limit`, which the current tables map at
        // `phys_to_virt(pa)`; nothing else references it.
        unsafe { core::ptr::write_bytes(phys_to_virt(pa) as *mut u8, 0, PAGE_SIZE) };
        Some(pa)
    }

    pub fn allocated(&self) -> usize {
        self.allocated
    }

    pub fn free_bytes(&self) -> usize {
        self.free.total()
    }
}

#[cfg(feature = "ktest")]
mod tests {
    use super::*;
    use crate::mm::{self, layout, virt_to_phys};

    ktest! {
        fn frames_are_zeroed_aligned_and_reserved_memory_is_skipped() {
            let info = crate::boot_info();
            let image = layout::kernel_layout().image;
            let image = Region::new(virt_to_phys(image.start), virt_to_phys(image.end));
            let mut previous = 0;
            for _ in 0..64 {
                let (pa, free_before, free_after) = mm::with_frames(|f| {
                    let before = f.free_bytes();
                    let pa = f.alloc();
                    (pa, before, f.free_bytes())
                });
                let pa = kunwrap!(pa.ok_or("out of frames"));
                kassert_eq!(pa % PAGE_SIZE, 0);
                kassert_eq!(free_before - free_after, PAGE_SIZE);
                kassert!(pa > previous, "frames must be distinct and ascending: {pa:#x} after {previous:#x}");
                previous = pa;
                let frame = Region::new(pa, pa + PAGE_SIZE);
                kassert!(info.platform.memory.as_slice().iter().any(|r| r.start <= pa && frame.end <= r.end));
                kassert!(!frame.overlaps(&image), "frame {pa:#x} inside the kernel image");
                kassert!(!frame.overlaps(&info.dtb.align_outward(PAGE_SIZE)), "frame {pa:#x} inside the DTB");
                // SAFETY: the frame was just allocated and is mapped through the linear map.
                let words = unsafe { core::slice::from_raw_parts(phys_to_virt(pa) as *const u64, PAGE_SIZE / 8) };
                kassert!(words.iter().all(|&w| w == 0), "frame {pa:#x} not zeroed");
            }
        }

        fn limit_is_respected() {
            let mut f = kunwrap!(FrameAllocator::new(&[Region::new(0x4000_0000, 0x4000_4000)], &[Region::new(0x4000_0000, 0x4000_1000)]));
            kassert_eq!(f.free_bytes(), 0x3000);
            f.set_limit(0x4000_1000);
            kassert_eq!(f.alloc(), None);
        }
    }
}
