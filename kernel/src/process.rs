//! Creating a user process from an ELF image: address space, program, stack, IPC buffer,
//! capability space and one thread. In B-1 only the kernel tests do this; from B-2 the
//! kernel starts the root task this way and user space builds everything else.

use aos_abi::layout;

use crate::cap::CNode;
use crate::elf::{self, ElfError};
use crate::kobj::KPtr;
use crate::mm::paging::{Attrs, PAGE_SIZE};
use crate::sched::Kernel;
use crate::thread::{Start, Thread};
use crate::vspace::{AddressSpace, VSpaceError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnError {
    Elf(ElfError),
    VSpace(VSpaceError),
    OutOfMemory,
}

impl From<ElfError> for SpawnError {
    fn from(e: ElfError) -> SpawnError {
        SpawnError::Elf(e)
    }
}

impl From<VSpaceError> for SpawnError {
    fn from(e: VSpaceError) -> SpawnError {
        SpawnError::VSpace(e)
    }
}

/// Loads `image` into a new address space and makes its first thread runnable with
/// `args` in x0/x1.
pub fn spawn(k: &mut Kernel, image: &[u8], priority: u8, args: [u64; 2]) -> Result<KPtr<Thread>, SpawnError> {
    let vs = AddressSpace::new(&mut k.asids)?;
    // SAFETY: the address space was just created; no other reference exists.
    let space = unsafe { vs.get() };
    let entry = elf::load(image, space)?;
    let stack_base = layout::STACK_TOP - layout::STACK_SIZE;
    for va in (stack_base..layout::STACK_TOP).step_by(PAGE_SIZE) {
        space.map_new(va, Attrs::USER_RW)?;
    }
    let ipc_buffer = space.map_new(layout::IPC_BUFFER, Attrs::USER_RW)?;
    let cspace = KPtr::new(CNode::new()).ok_or(SpawnError::OutOfMemory)?;
    let id = k.next_thread_id();
    let start = Start { entry, stack_top: layout::STACK_TOP, args };
    let thread = Thread::new(id, vs, cspace, start, priority, Some(ipc_buffer));
    let t = KPtr::new(thread).ok_or(SpawnError::OutOfMemory)?;
    k.make_ready(t);
    Ok(t)
}
