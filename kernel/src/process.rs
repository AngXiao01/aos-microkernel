//! Processes the kernel builds itself from an ELF image: the root task, and the B-1 test
//! programs. Their objects come from the boot allocator; the thread holds its capability
//! space, address space and IPC buffer as binding capabilities, like any thread.

use aos_abi::layout;

use crate::cap::{self, CNode, Cap};
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

pub struct Process {
    pub thread: KPtr<Thread>,
    pub cnode: KPtr<CNode>,
    pub space: KPtr<AddressSpace>,
}

/// Loads `image` into a new address space with a stack and an IPC buffer, and creates an
/// inactive thread bound to it with `args` in x0/x1.
pub fn build(k: &mut Kernel, image: &[u8], priority: u8, args: [u64; 2]) -> Result<Process, SpawnError> {
    let space = k.spaces.create_boot()?;
    // SAFETY: the address space was just created; no other reference exists.
    let s = unsafe { space.get() };
    let entry = elf::load(image, s)?;
    for va in (layout::STACK_TOP - layout::STACK_SIZE..layout::STACK_TOP).step_by(PAGE_SIZE) {
        s.map_new(va, Attrs::USER_RW)?;
    }
    let ipc = s.map_new(layout::IPC_BUFFER, Attrs::USER_RW)?;
    let mapping = s.mapping(layout::IPC_BUFFER);
    // SAFETY: all-zero bytes are an empty CNode.
    let cnode = unsafe { KPtr::<CNode>::zeroed() }.ok_or(SpawnError::OutOfMemory)?;
    let thread = KPtr::new(Thread::new(0)).ok_or(SpawnError::OutOfMemory)?;
    k.register(thread);
    // SAFETY: the thread was just created; the binding slots are inside it.
    unsafe {
        let th = thread.get();
        th.priority = priority;
        th.set_start(Start { entry, stack_top: layout::STACK_TOP, args });
        cap::insert(KPtr::from_mut(&mut th.cspace_slot), Cap::CNode(cnode), None);
        cap::insert(KPtr::from_mut(&mut th.vspace_slot), Cap::AddressSpace(space), None);
        cap::insert(
            KPtr::from_mut(&mut th.ipc_slot),
            Cap::Frame { pa: ipc, writable: true, mapped: Some(mapping) },
            None,
        );
    }
    Ok(Process { thread, cnode, space })
}

/// `build`, then make the thread runnable.
pub fn spawn(k: &mut Kernel, image: &[u8], priority: u8, args: [u64; 2]) -> Result<KPtr<Thread>, SpawnError> {
    let p = build(k, image, priority, args)?;
    k.make_ready(p.thread);
    Ok(p.thread)
}
