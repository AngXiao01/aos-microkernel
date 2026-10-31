//! User address spaces: a TTBR0 translation table tagged with an ASID.
//!
//! An address space made from Untyped memory is one 64 KiB object: its header, its L0
//! table and a pool of pages for the lower-level tables, so its tables live and die with
//! it. Spaces the kernel builds itself (root task, B-1 tests) take tables from the boot
//! allocator. The ASID table names each live space by (ASID, generation); frame
//! capabilities record mappings that way, so a stale mapping can never touch a later space.

use aos_abi::{layout, object};

use crate::arch::mmu;
use crate::cap::Mapping;
use crate::kobj::KPtr;
use crate::mm::paging::{self, Attrs, MapError, PAGE_SIZE, PageSize, TableAlloc};
use crate::mm::{self, phys_to_virt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VSpaceError {
    OutOfMemory,
    OutOfAsids,
    NotUserAddress,
    Map(MapError),
}

impl From<MapError> for VSpaceError {
    fn from(e: MapError) -> VSpaceError {
        VSpaceError::Map(e)
    }
}

/// Table pages inside an address space object.
#[derive(Clone, Copy)]
struct Pool {
    next: usize,
    end: usize,
}

impl TableAlloc for Pool {
    fn table(&mut self) -> Option<usize> {
        if self.next + PAGE_SIZE > self.end {
            return None;
        }
        let pa = self.next;
        self.next += PAGE_SIZE;
        // SAFETY: the page belongs to this address space object and is mapped in the linear map.
        unsafe { core::ptr::write_bytes(phys_to_virt(pa) as *mut u8, 0, PAGE_SIZE) };
        Some(pa)
    }
}

pub struct AddressSpace {
    pub refs: u32,
    /// Physical address of the L0 table.
    pub root: usize,
    pub asid: u16,
    pub generation: u32,
    /// `None`: tables come from the boot allocator.
    pool: Option<Pool>,
}

impl AddressSpace {
    /// Maps one 4 KiB page of user memory.
    pub fn map(&mut self, va: u64, pa: usize, attrs: Attrs) -> Result<(), VSpaceError> {
        if !(layout::USER_MIN..layout::USER_END).contains(&va) {
            return Err(VSpaceError::NotUserAddress);
        }
        let root = self.root;
        let r = match &mut self.pool {
            Some(pool) => paging::map(root, va as usize, pa, PageSize::Page4K, attrs, pool),
            None => mm::with_frames(|f| paging::map(root, va as usize, pa, PageSize::Page4K, attrs, f)),
        };
        r.map_err(|e| if e == MapError::OutOfMemory { VSpaceError::OutOfMemory } else { VSpaceError::Map(e) })
    }

    /// Gives a space built from boot memory its own table pool, for mappings made after the
    /// boot allocator is sealed (the root task maps frames into itself at run time).
    pub fn attach_pool(&mut self, pa: usize, size: usize) {
        self.pool = Some(Pool { next: pa, end: pa + size });
    }

    /// Allocates a zeroed boot frame, maps it at `va` and returns its physical address.
    pub fn map_new(&mut self, va: u64, attrs: Attrs) -> Result<usize, VSpaceError> {
        let pa = mm::with_frames(|f| f.alloc()).ok_or(VSpaceError::OutOfMemory)?;
        self.map(va, pa, attrs)?;
        Ok(pa)
    }

    pub fn activate(&self) {
        mmu::set_user_space(self.root, self.asid);
    }

    pub fn mapping(&self, va: u64) -> Mapping {
        Mapping { asid: self.asid, generation: self.generation, va }
    }
}

/// The live address spaces by ASID (8-bit, ASID 0 is never used).
pub struct Spaces {
    live: [Option<KPtr<AddressSpace>>; 256],
    generation: [u32; 256],
}

impl Spaces {
    pub const fn new() -> Spaces {
        Spaces { live: [None; 256], generation: [0; 256] }
    }

    pub fn free_asids(&self) -> usize {
        (1..256).filter(|&i| self.live[i].is_none()).count()
    }

    fn free_asid(&self) -> Option<u16> {
        (1..256).find(|&i| self.live[i].is_none()).map(|i| i as u16)
    }

    fn register(&mut self, asid: u16, a: KPtr<AddressSpace>) {
        self.live[asid as usize] = Some(a);
    }

    /// A space whose tables come from the boot allocator.
    pub fn create_boot(&mut self) -> Result<KPtr<AddressSpace>, VSpaceError> {
        let asid = self.free_asid().ok_or(VSpaceError::OutOfAsids)?;
        let root = mm::with_frames(|f| f.alloc()).ok_or(VSpaceError::OutOfMemory)?;
        let generation = self.generation[asid as usize];
        let a =
            KPtr::new(AddressSpace { refs: 0, root, asid, generation, pool: None }).ok_or(VSpaceError::OutOfMemory)?;
        self.register(asid, a);
        Ok(a)
    }

    /// A space in the zeroed `object::ADDRESS_SPACE` bytes at `pa` (carved from Untyped):
    /// header in the first page, the L0 table in the second, table pool in the rest.
    ///
    /// # Safety
    /// The bytes must be RAM owned by the new object.
    pub unsafe fn create_in(&mut self, pa: usize) -> Result<KPtr<AddressSpace>, VSpaceError> {
        let asid = self.free_asid().ok_or(VSpaceError::OutOfAsids)?;
        let size = object::size(object::ADDRESS_SPACE).expect("known object") as usize;
        let pool = Pool { next: pa + 2 * PAGE_SIZE, end: pa + size };
        let space = AddressSpace {
            refs: 0,
            root: pa + PAGE_SIZE,
            asid,
            generation: self.generation[asid as usize],
            pool: Some(pool),
        };
        // SAFETY: the caller carved `size` zeroed bytes at `pa` for this object.
        let a = unsafe { KPtr::place(pa, space) };
        self.register(asid, a);
        Ok(a)
    }

    fn lookup(&self, m: Mapping) -> Option<KPtr<AddressSpace>> {
        let a = self.live[m.asid as usize]?;
        (self.generation[m.asid as usize] == m.generation).then_some(a)
    }

    /// Removes a frame mapping, if its address space still exists.
    pub fn unmap(&mut self, m: Mapping) {
        if let Some(a) = self.lookup(m) {
            // SAFETY: a live address space; nothing else references it here.
            let root = unsafe { a.get() }.root;
            let _ = paging::unmap(root, m.va as usize);
        }
    }

    /// The last capability to `a` is gone: retire its ASID. Its tables die with its memory.
    pub fn destroy(&mut self, a: KPtr<AddressSpace>) {
        // SAFETY: the object is still intact; its last capability was just deleted.
        let asid = unsafe { a.get() }.asid;
        self.live[asid as usize] = None;
        self.generation[asid as usize] = self.generation[asid as usize].wrapping_add(1);
        mmu::flush_asid(asid);
    }
}
