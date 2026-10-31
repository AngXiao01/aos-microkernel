//! Methods of kernel objects: `CALL` on an Untyped, CNode, thread, address space, frame or
//! debug capability (labels in `aos_abi::method`). Capability arguments are slots in the
//! caller's CNode. The methods take the caller's CNode rather than the caller, so the
//! kernel tests can drive them directly.

use aos_abi::{CNODE_SLOTS, Error, MsgInfo, method, object, rights};

use crate::cap::{self, CNode, Cap, Slot};
use crate::ipc::{Endpoint, Notification};
use crate::kobj::KPtr;
use crate::mm::paging::{Attrs, MapError};
use crate::mm::phys_to_virt;
use crate::mm::region::align_up;
use crate::sched::Kernel;
use crate::thread::{Thread, ThreadState};
use crate::vspace::VSpaceError;

pub type Reply = Result<[u64; 4], Error>;

const OK: Reply = Ok([0; 4]);

// SAFETY (for the `get` calls below): live kernel objects; single-threaded kernel; each
// function holds at most one reference to any slot or object at a time.

fn slot_of(cnode: KPtr<CNode>, index: u64) -> Result<KPtr<Slot>, Error> {
    // SAFETY: see above.
    unsafe { cnode.get() }.slot(index).ok_or(Error::InvalidArgument)
}

fn cap_of(slot: KPtr<Slot>) -> Cap {
    // SAFETY: see above.
    unsafe { slot.get() }.cap
}

fn empty(slot: KPtr<Slot>) -> Result<KPtr<Slot>, Error> {
    if cap_of(slot) == Cap::Null { Ok(slot) } else { Err(Error::SlotInUse) }
}

/// Handles `CALL` on a kernel object capability for thread `t`.
pub fn invoke(k: &mut Kernel, t: KPtr<Thread>, index: u64) {
    // SAFETY: see above; the reference ends here.
    let (label, args, cnode, priority) = {
        let th = unsafe { t.get() };
        (MsgInfo(th.ctx.x[1]).label(), [th.ctx.x[2], th.ctx.x[3], th.ctx.x[4], th.ctx.x[5]], th.cnode(), th.priority)
    };
    let result = match cnode {
        Some(cnode) => dispatch(k, cnode, priority, index, label, args),
        None => Err(Error::InvalidCap),
    };
    // The method may have destroyed the caller (deleting its own thread capability).
    if !k.is_live(t) {
        return;
    }
    // SAFETY: see above.
    let th = unsafe { t.get() };
    match result {
        Ok(words) => {
            th.set_status(Error::Ok);
            th.ctx.x[1] = MsgInfo::new(0, 4).0;
            th.ctx.x[2..6].copy_from_slice(&words);
        }
        Err(e) => th.set_status(e),
    }
}

/// One method call; `priority` is the caller's (threads cannot be given more).
pub fn dispatch(k: &mut Kernel, cnode: KPtr<CNode>, priority: u8, index: u64, label: u64, a: [u64; 4]) -> Reply {
    let slot = cnode_slot(cnode, index)?;
    match (cap_of(slot), label) {
        (Cap::Untyped { .. }, method::RETYPE) => retype(k, cnode, slot, a[0], a[1], a[2]),
        (Cap::CNode(target), method::COPY) => copy(cnode, target, a[0], a[1], a[2], None),
        (Cap::CNode(target), method::MINT) => copy(cnode, target, a[0], a[1], a[2], Some(a[3])),
        (Cap::CNode(target), method::MOVE) => {
            let (src, dest) = (slot_of(cnode, a[0])?, empty(slot_of(target, a[1])?)?);
            cap::move_slot(src, dest);
            OK
        }
        (Cap::CNode(target), method::DELETE) => {
            cap::delete(k, slot_of(target, a[0])?);
            OK
        }
        (Cap::CNode(target), method::REVOKE) => {
            cap::revoke(k, slot_of(target, a[0])?);
            OK
        }
        (Cap::Thread(target), method::CONFIGURE) => configure(cnode, priority, target, a),
        (Cap::Thread(target), method::WRITE_REGISTERS) => {
            // SAFETY: see above.
            let th = unsafe { target.get() };
            if th.state != ThreadState::Inactive {
                return Err(Error::InvalidArgument);
            }
            th.set_start(crate::thread::Start { entry: a[0], stack_top: a[1], args: [a[2], a[3]] });
            OK
        }
        (Cap::Thread(target), method::RESUME) => {
            // SAFETY: see above.
            let th = unsafe { target.get() };
            if th.state != ThreadState::Inactive || th.cnode().is_none() || th.space().is_none() {
                return Err(Error::InvalidArgument);
            }
            th.exit = None;
            k.make_ready(target);
            OK
        }
        (Cap::Thread(target), method::SUSPEND) => {
            k.suspend(target);
            OK
        }
        (Cap::AddressSpace(space), method::MAP) => map(cnode, space, a[0], a[1], a[2]),
        (Cap::AddressSpace(space), method::MAP_DEVICE) => map_device(cnode, space, a[0], a[1]),
        (Cap::Frame { pa, .. }, method::PHYS) => Ok([pa as u64, 4096, 0, 0]),
        (Cap::Irq { index }, method::IRQ_BIND) => bind_irq(cnode, index, a[0]),
        (Cap::Irq { index }, method::IRQ_ACK) => {
            crate::irq::ack(index as usize);
            OK
        }
        (Cap::Frame { mapped, .. }, method::UNMAP) => {
            if let Some(m) = mapped {
                k.spaces.unmap(m);
            }
            // SAFETY: see above.
            if let Cap::Frame { mapped, .. } = &mut unsafe { slot.get() }.cap {
                *mapped = None;
            }
            OK
        }
        (Cap::Debug, method::DUMP_CAPS) => {
            dump(k);
            OK
        }
        (Cap::Null | Cap::Endpoint { .. } | Cap::Notification { .. }, _) => Err(Error::InvalidCap),
        _ => Err(Error::UnknownMethod),
    }
}

fn cnode_slot(cnode: KPtr<CNode>, index: u64) -> Result<KPtr<Slot>, Error> {
    slot_of(cnode, index).map_err(|_| Error::InvalidCap)
}

/// Carves `count` objects of `kind` from the Untyped in `slot` into the caller's slots
/// `dest..dest + count`. Either all are made or none.
pub fn retype(k: &mut Kernel, cnode: KPtr<CNode>, slot: KPtr<Slot>, kind: u64, dest: u64, count: u64) -> Reply {
    let Cap::Untyped { base, size_bits, free } = cap_of(slot) else { return Err(Error::InvalidCap) };
    let size = object::size(kind).ok_or(Error::InvalidArgument)? as usize;
    if count == 0 || count > CNODE_SLOTS || dest.checked_add(count).is_none_or(|end| end > CNODE_SLOTS) {
        return Err(Error::InvalidArgument);
    }
    let start = align_up(free, size);
    let end = start.checked_add(size * count as usize).ok_or(Error::NoMemory)?;
    if end > 1usize << size_bits {
        return Err(Error::NoMemory);
    }
    for i in 0..count {
        empty(slot_of(cnode, dest + i)?)?;
    }
    if kind == object::ADDRESS_SPACE && k.spaces.free_asids() < count as usize {
        return Err(Error::NoMemory);
    }
    for i in 0..count as usize {
        let pa = base + start + i * size;
        // SAFETY: `[pa, pa + size)` lies in this Untyped beyond its free index, so nothing
        // uses it; it is RAM mapped in the linear map.
        unsafe { core::ptr::write_bytes(phys_to_virt(pa) as *mut u8, 0, size) };
        // SAFETY: as above: the memory belongs to the new object.
        let cap = unsafe { make(k, kind, pa) };
        cap::insert(slot_of(cnode, dest + i as u64)?, cap, Some(slot));
    }
    // SAFETY: see above.
    if let Cap::Untyped { free, .. } = &mut unsafe { slot.get() }.cap {
        *free = end;
    }
    OK
}

/// # Safety
/// `pa` must be zeroed RAM of `object::size(kind)` bytes owned by the new object.
unsafe fn make(k: &mut Kernel, kind: u64, pa: usize) -> Cap {
    // SAFETY (all arms): guaranteed by the caller; zeroed memory is a valid empty CNode.
    unsafe {
        match kind {
            object::ENDPOINT => {
                Cap::Endpoint { ep: KPtr::place(pa, Endpoint::new()), badge: 0, rights: cap::Rights::ALL }
            }
            object::NOTIFICATION => {
                Cap::Notification { ntfn: KPtr::place(pa, Notification::new()), badge: 0, rights: cap::Rights::ALL }
            }
            object::THREAD => {
                let t = KPtr::place(pa, Thread::new(0));
                k.register(t);
                Cap::Thread(t)
            }
            object::CNODE => Cap::CNode(KPtr::from_mut(&mut *(phys_to_virt(pa) as *mut CNode))),
            object::ADDRESS_SPACE => Cap::AddressSpace(k.spaces.create_in(pa).expect("ASIDs checked")),
            _ => Cap::Frame { pa, writable: true, mapped: None },
        }
    }
}

/// COPY and MINT: a copy of the caller's capability `src` into `target[dest]`.
fn copy(cnode: KPtr<CNode>, target: KPtr<CNode>, src: u64, dest: u64, mask: u64, badge: Option<u64>) -> Reply {
    let from = slot_of(cnode, src)?;
    let to = empty(slot_of(target, dest)?)?;
    let derived = cap::derive(cap_of(from), mask, badge).ok_or(Error::InvalidArgument)?;
    cap::insert(to, derived, Some(from));
    OK
}

/// Binds a thread to a capability space, address space and IPC buffer (copies of the
/// caller's capabilities) and sets its priority.
fn configure(cnode: KPtr<CNode>, caller_priority: u8, target: KPtr<Thread>, a: [u64; 4]) -> Reply {
    let [cnode_index, space_index, ipc_index, priority] = a;
    // SAFETY: see above.
    if unsafe { target.get() }.state != ThreadState::Inactive {
        return Err(Error::InvalidArgument);
    }
    if priority > u64::from(caller_priority) {
        return Err(Error::NoRight);
    }
    let (cs, vs) = (slot_of(cnode, cnode_index)?, slot_of(cnode, space_index)?);
    let ipc = if ipc_index == 0 { None } else { Some(slot_of(cnode, ipc_index)?) };
    if !matches!(cap_of(cs), Cap::CNode(_))
        || !matches!(cap_of(vs), Cap::AddressSpace(_))
        || ipc.is_some_and(|s| !matches!(cap_of(s), Cap::Frame { writable: true, .. }))
    {
        return Err(Error::InvalidCap);
    }
    // SAFETY: see above; the binding slots live inside the thread object.
    let bindings = unsafe {
        let th = target.get();
        th.priority = priority as u8;
        [KPtr::from_mut(&mut th.cspace_slot), KPtr::from_mut(&mut th.vspace_slot), KPtr::from_mut(&mut th.ipc_slot)]
    };
    if bindings.iter().any(|b| cap_of(*b) != Cap::Null) {
        return Err(Error::SlotInUse); // already configured: bindings are set once
    }
    for (binding, source) in bindings.into_iter().zip([Some(cs), Some(vs), ipc]) {
        if let Some(src) = source {
            let derived = cap::derive(cap_of(src), rights::ALL, None).ok_or(Error::InvalidCap)?;
            cap::insert(binding, derived, Some(src));
        }
    }
    OK
}

/// Maps the caller's frame `frame_index` at `va` in `space` with `rights` (W^X).
fn map(cnode: KPtr<CNode>, space: KPtr<crate::vspace::AddressSpace>, frame_index: u64, va: u64, rights: u64) -> Reply {
    let slot = slot_of(cnode, frame_index)?;
    let Cap::Frame { pa, writable, mapped } = cap_of(slot) else { return Err(Error::InvalidCap) };
    if mapped.is_some() {
        return Err(Error::AlreadyMapped);
    }
    let (w, x) = (rights & method::WRITE != 0, rights & method::EXECUTE != 0);
    if w && x {
        return Err(Error::InvalidArgument);
    }
    if w && !writable {
        return Err(Error::NoRight);
    }
    let attrs = if w {
        Attrs::USER_RW
    } else if x {
        Attrs::USER_RX
    } else {
        Attrs::USER_RO
    };
    // SAFETY: see above.
    let s = unsafe { space.get() };
    s.map(va, pa, attrs).map_err(|e| match e {
        VSpaceError::OutOfMemory | VSpaceError::OutOfAsids => Error::NoMemory,
        VSpaceError::Map(MapError::AlreadyMapped) => Error::AlreadyMapped,
        _ => Error::InvalidArgument,
    })?;
    let mapping = s.mapping(va);
    // SAFETY: see above.
    if let Cap::Frame { mapped, .. } = &mut unsafe { slot.get() }.cap {
        *mapped = Some(mapping);
    }
    OK
}

/// Maps the caller's DeviceMMIO capability at `va` as device memory.
fn map_device(cnode: KPtr<CNode>, space: KPtr<crate::vspace::AddressSpace>, dev_index: u64, va: u64) -> Reply {
    let slot = slot_of(cnode, dev_index)?;
    let Cap::Device { pa, mapped } = cap_of(slot) else { return Err(Error::InvalidCap) };
    if mapped.is_some() {
        return Err(Error::AlreadyMapped);
    }
    if !va.is_multiple_of(4096) {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: see above.
    let s = unsafe { space.get() };
    s.map(va, pa, Attrs::USER_DEVICE).map_err(|e| match e {
        VSpaceError::OutOfMemory | VSpaceError::OutOfAsids => Error::NoMemory,
        VSpaceError::Map(MapError::AlreadyMapped) => Error::AlreadyMapped,
        _ => Error::InvalidArgument,
    })?;
    let mapping = s.mapping(va);
    // SAFETY: see above.
    if let Cap::Device { mapped, .. } = &mut unsafe { slot.get() }.cap {
        *mapped = Some(mapping);
    }
    OK
}

fn bind_irq(cnode: KPtr<CNode>, index: u8, ntfn_index: u64) -> Reply {
    let Cap::Notification { ntfn, .. } = cap_of(slot_of(cnode, ntfn_index)?) else {
        return Err(Error::InvalidCap);
    };
    crate::irq::bind(index as usize, ntfn);
    OK
}

/// What one capability space holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Holdings {
    pub caps: u32,
    pub untyped_caps: u32,
    pub untyped_bytes: u64,
    pub frames: u32,
    pub endpoints: u32,
    pub threads: u32,
    pub debug: bool,
}

pub fn holdings(cnode: KPtr<CNode>) -> Holdings {
    let mut h = Holdings::default();
    // SAFETY: see above.
    for slot in unsafe { cnode.get() }.slots() {
        match slot.cap {
            Cap::Null => continue,
            Cap::Untyped { size_bits, .. } => {
                h.untyped_caps += 1;
                h.untyped_bytes += 1 << size_bits;
            }
            Cap::Frame { .. } => h.frames += 1,
            Cap::Endpoint { .. } => h.endpoints += 1,
            Cap::Thread(_) => h.threads += 1,
            Cap::Debug => h.debug = true,
            _ => {}
        }
        h.caps += 1;
    }
    h
}

/// The capability audit (§B10): one line per thread with what its capability space holds.
pub fn dump(k: &Kernel) {
    for t in k.threads() {
        // SAFETY: see above.
        let (id, state, cnode) = unsafe {
            let th = t.get();
            (th.id, th.state, th.cnode())
        };
        let h = cnode.map(holdings).unwrap_or_default();
        kprintln!("caps: thread {id} {state:?}: {h:?}");
    }
}
