//! ELF64 loader for user programs: statically linked AArch64 executables, each `PT_LOAD`
//! segment mapped with exactly its permissions. Writable-and-executable segments are
//! refused (W^X).

use aos_abi::layout;

use crate::mm::paging::{Attrs, PAGE_SIZE};
use crate::mm::phys_to_virt;
use crate::mm::region::{align_down, align_up};
use crate::vspace::{AddressSpace, VSpaceError};

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const EM_AARCH64: u16 = 183;
const ET_EXEC: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// Not a little-endian ELF64 AArch64 executable.
    NotAnExecutable,
    Truncated,
    /// A segment is writable and executable, outside user space, or inconsistent.
    BadSegment,
    /// The entry point is not in an executable segment.
    BadEntry,
    VSpace(VSpaceError),
}

impl From<VSpaceError> for ElfError {
    fn from(e: VSpaceError) -> ElfError {
        ElfError::VSpace(e)
    }
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, ElfError> {
    let s = b.get(off..off + 2).ok_or(ElfError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, ElfError> {
    let s = b.get(off..off + 4).ok_or(ElfError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], off: usize) -> Result<u64, ElfError> {
    let s = b.get(off..off + 8).ok_or(ElfError::Truncated)?;
    Ok(u64::from_le_bytes(s.try_into().map_err(|_| ElfError::Truncated)?))
}

/// Maps the program into `vs` (fresh zeroed frames, file contents copied in) and returns
/// its entry point.
pub fn load(image: &[u8], vs: &mut AddressSpace) -> Result<u64, ElfError> {
    if image.get(..7) != Some(&[0x7f, b'E', b'L', b'F', 2, 1, 1])
        || u16_at(image, 16)? != ET_EXEC
        || u16_at(image, 18)? != EM_AARCH64
    {
        return Err(ElfError::NotAnExecutable);
    }
    let entry = u64_at(image, 24)?;
    let phoff = u64_at(image, 32)? as usize;
    let phentsize = u16_at(image, 54)? as usize;
    let phnum = u16_at(image, 56)? as usize;
    if phentsize < 56 {
        return Err(ElfError::NotAnExecutable);
    }
    let mut entry_ok = false;
    for i in 0..phnum {
        let ph = phoff.checked_add(i * phentsize).ok_or(ElfError::Truncated)?;
        if u32_at(image, ph)? != PT_LOAD {
            continue;
        }
        let flags = u32_at(image, ph + 4)?;
        let offset = u64_at(image, ph + 8)? as usize;
        let vaddr = u64_at(image, ph + 16)?;
        let filesz = u64_at(image, ph + 32)?;
        let memsz = u64_at(image, ph + 40)?;
        let end = vaddr.checked_add(memsz).ok_or(ElfError::BadSegment)?;
        if flags & PF_X != 0 && flags & PF_W != 0
            || filesz > memsz
            || vaddr < layout::USER_MIN
            || end > layout::USER_END
        {
            return Err(ElfError::BadSegment);
        }
        let file = image.get(offset..offset.checked_add(filesz as usize).ok_or(ElfError::Truncated)?);
        let file = file.ok_or(ElfError::Truncated)?;
        let attrs = if flags & PF_X != 0 {
            Attrs::USER_RX
        } else if flags & PF_W != 0 {
            Attrs::USER_RW
        } else {
            Attrs::USER_RO
        };
        if flags & PF_X != 0 && (vaddr..end).contains(&entry) {
            entry_ok = true;
        }
        let page = PAGE_SIZE as u64;
        for page_va in
            (align_down(vaddr as usize, PAGE_SIZE) as u64..align_up(end as usize, PAGE_SIZE) as u64).step_by(PAGE_SIZE)
        {
            let pa = vs.map_new(page_va, attrs)?;
            // Copy the part of the file image that falls into this page.
            let from = vaddr.max(page_va);
            let to = (vaddr + filesz).min(page_va + page);
            if from < to {
                let src = &file[(from - vaddr) as usize..(to - vaddr) as usize];
                let dst = phys_to_virt(pa) + (from - page_va) as usize;
                // SAFETY: `pa` is a fresh frame in the linear map; the range stays in it.
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut u8, src.len()) };
            }
        }
    }
    if !entry_ok {
        return Err(ElfError::BadEntry);
    }
    Ok(entry)
}
