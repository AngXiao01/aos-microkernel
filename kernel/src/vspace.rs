//! User address spaces: a TTBR0 translation table tagged with an ASID.

use aos_abi::layout;

use crate::arch::mmu;
use crate::kobj::KPtr;
use crate::mm::{self, paging};
use paging::{Attrs, MapError, PageSize};

/// 8-bit ASIDs (TCR_EL1.AS = 0); ASID 0 is never handed out.
pub struct AsidAllocator {
    used: [u64; 4],
}

impl AsidAllocator {
    pub const fn new() -> AsidAllocator {
        AsidAllocator { used: [1, 0, 0, 0] }
    }

    fn alloc(&mut self) -> Option<u16> {
        let (word, bits) = self.used.iter_mut().enumerate().find(|(_, w)| **w != u64::MAX)?;
        let bit = bits.trailing_ones();
        *bits |= 1 << bit;
        Some((word as u32 * 64 + bit) as u16)
    }
}

pub struct AddressSpace {
    /// Physical address of the L0 table.
    pub root: usize,
    pub asid: u16,
}

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

impl AddressSpace {
    pub fn new(asids: &mut AsidAllocator) -> Result<KPtr<AddressSpace>, VSpaceError> {
        let asid = asids.alloc().ok_or(VSpaceError::OutOfAsids)?;
        let root = mm::with_frames(|f| f.alloc()).ok_or(VSpaceError::OutOfMemory)?;
        KPtr::new(AddressSpace { root, asid }).ok_or(VSpaceError::OutOfMemory)
    }

    /// Maps one 4 KiB page of user memory.
    pub fn map(&mut self, va: u64, pa: usize, attrs: Attrs) -> Result<(), VSpaceError> {
        if !(layout::USER_MIN..layout::USER_END).contains(&va) {
            return Err(VSpaceError::NotUserAddress);
        }
        let root = self.root;
        Ok(mm::with_frames(|f| paging::map(root, va as usize, pa, PageSize::Page4K, attrs, f))?)
    }

    /// Allocates a zeroed frame, maps it at `va` and returns its physical address.
    pub fn map_new(&mut self, va: u64, attrs: Attrs) -> Result<usize, VSpaceError> {
        let pa = mm::with_frames(|f| f.alloc()).ok_or(VSpaceError::OutOfMemory)?;
        self.map(va, pa, attrs)?;
        Ok(pa)
    }

    pub fn activate(&self) {
        mmu::set_user_space(self.root, self.asid);
    }
}
