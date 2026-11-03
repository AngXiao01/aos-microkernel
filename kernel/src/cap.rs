//! Capabilities, capability spaces and the derivation tree (§B3.1).
//!
//! Every capability lives in a slot. Slots form a derivation tree: objects carved from an
//! Untyped are its children, copies and mints are children of their source. Deleting a slot
//! hands its children to its parent; revoking a slot deletes all its descendants. Kernel
//! objects count the capabilities that name them and are destroyed with the last one, so
//! revoking an Untyped destroys everything made from it before its memory can be reused.
//!
//! A thread's address space, capability space and IPC buffer are capabilities held in slots
//! inside the thread object, children of the capabilities they were configured from. So no
//! object can vanish while a thread still uses it, except by revocation, which also deletes
//! the thread's binding and thereby stops the thread.

use aos_abi::{CNODE_SLOTS, rights};

use crate::ipc::{Endpoint, Notification};
use crate::kobj::KPtr;
use crate::sched::Kernel;
use crate::thread::Thread;
use crate::vspace::AddressSpace;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(u8);

impl Rights {
    pub const SEND: Rights = Rights(rights::SEND as u8);
    pub const RECV: Rights = Rights(rights::RECV as u8);
    pub const GRANT: Rights = Rights(rights::GRANT as u8);
    pub const ALL: Rights = Rights(rights::ALL as u8);

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn masked(self, mask: u64) -> Rights {
        Rights(self.0 & mask as u8)
    }
}

/// Where a frame is mapped. The address space is named by ASID and generation, so a
/// mapping recorded in a capability can never reach a later address space with the same ASID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub asid: u16,
    pub generation: u32,
    pub va: u64,
}

/// `#[repr(u8)]` with `Null` as 0: zeroed memory is an empty slot.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    Null = 0,
    /// `[base, base + 2^size_bits)`; objects are carved from `free` on. Untyped
    /// capabilities are never copied, so `free` belongs to exactly one capability.
    Untyped {
        base: usize,
        size_bits: u8,
        free: usize,
    },
    Frame {
        pa: usize,
        writable: bool,
        mapped: Option<Mapping>,
    },
    /// The badge is delivered to receivers and tells them which capability was used.
    Endpoint {
        ep: KPtr<Endpoint>,
        badge: u64,
        rights: Rights,
    },
    /// Signalling sets the badge's bits (bit 0 if the badge is 0).
    Notification {
        ntfn: KPtr<Notification>,
        badge: u64,
        rights: Rights,
    },
    Thread(KPtr<Thread>),
    AddressSpace(KPtr<AddressSpace>),
    CNode(KPtr<CNode>),
    /// The capability audit (§B10); debug kernels only.
    Debug,
    /// One 4 KiB MMIO page. Not carved from Untyped: the kernel creates it at boot.
    Device {
        pa: usize,
        mapped: Option<Mapping>,
    },
    /// A hardware interrupt line. `index` names the kernel's binding slot.
    Irq {
        index: u8,
    },
}

pub struct Slot {
    pub cap: Cap,
    parent: Option<KPtr<Slot>>,
    first_child: Option<KPtr<Slot>>,
    next: Option<KPtr<Slot>>,
    prev: Option<KPtr<Slot>>,
}

impl Slot {
    pub const EMPTY: Slot = Slot { cap: Cap::Null, parent: None, first_child: None, next: None, prev: None };
}

/// A capability space. Zeroed memory is a valid, empty CNode.
pub struct CNode {
    pub refs: u32,
    slots: [Slot; CNODE_SLOTS as usize],
}

impl CNode {
    /// The capability in `slot`; `Null` for out-of-range slots.
    pub fn get(&self, slot: u64) -> Cap {
        usize::try_from(slot).ok().and_then(|i| self.slots.get(i)).map_or(Cap::Null, |s| s.cap)
    }

    pub fn slot(&mut self, slot: u64) -> Option<KPtr<Slot>> {
        let s = self.slots.get_mut(usize::try_from(slot).ok()?)?;
        Some(KPtr::from_mut(s))
    }

    pub fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.slots.iter()
    }
}

// SAFETY (for the `get` calls in this module): slots and objects are live kernel objects;
// the kernel is single-threaded and each function holds at most one reference to any slot
// or object at a time.

/// Counts a new capability to an object.
fn retain(cap: &Cap) {
    // SAFETY: see above.
    unsafe {
        match cap {
            Cap::Endpoint { ep, .. } => ep.get().refs += 1,
            Cap::Notification { ntfn, .. } => ntfn.get().refs += 1,
            Cap::Thread(t) => t.get().refs += 1,
            Cap::AddressSpace(a) => a.get().refs += 1,
            Cap::CNode(c) => c.get().refs += 1,
            Cap::Null | Cap::Untyped { .. } | Cap::Frame { .. } | Cap::Debug | Cap::Device { .. } | Cap::Irq { .. } => {
            }
        }
    }
}

/// Puts `cap` into the empty slot `dest`, as a child of `parent` (or a root).
pub fn insert(dest: KPtr<Slot>, cap: Cap, parent: Option<KPtr<Slot>>) {
    retain(&cap);
    // SAFETY: see above; `dest` is empty and distinct from `parent`.
    unsafe {
        let d = dest.get();
        debug_assert!(d.cap == Cap::Null);
        *d = Slot { cap, parent, first_child: None, next: None, prev: None };
        if let Some(p) = parent {
            let first = p.get().first_child;
            d.next = first;
            if let Some(f) = first {
                f.get().prev = Some(dest);
            }
            p.get().first_child = Some(dest);
        }
    }
}

/// A capability derived from `cap` for a copy: rights reduced to `mask`, an unbadged
/// endpoint or notification badged with `badge`. Untyped capabilities cannot be copied
/// (their free index must stay unique); a copied frame starts unmapped.
pub fn derive(cap: Cap, mask: u64, badge: Option<u64>) -> Option<Cap> {
    let rebadge = |current: u64| match badge {
        Some(b) if current == 0 => b,
        _ => current,
    };
    match cap {
        Cap::Null | Cap::Untyped { .. } => None,
        Cap::Frame { pa, writable, .. } => {
            Some(Cap::Frame { pa, writable: writable && mask & rights::SEND != 0, mapped: None })
        }
        Cap::Endpoint { ep, badge: b, rights } => {
            Some(Cap::Endpoint { ep, badge: rebadge(b), rights: rights.masked(mask) })
        }
        Cap::Notification { ntfn, badge: b, rights } => {
            Some(Cap::Notification { ntfn, badge: rebadge(b), rights: rights.masked(mask) })
        }
        Cap::Device { pa, .. } => Some(Cap::Device { pa, mapped: None }),
        Cap::Irq { index } => Some(Cap::Irq { index }),
        other => Some(other),
    }
}

/// Moves the capability from `src` to the empty slot `dest`, keeping its place in the tree.
pub fn move_slot(src: KPtr<Slot>, dest: KPtr<Slot>) {
    if src == dest {
        return;
    }
    // SAFETY: see above; `src != dest`.
    unsafe {
        let moved = core::mem::replace(src.get(), Slot::EMPTY);
        *dest.get() = moved;
        let d = dest.get();
        if let Some(p) = d.parent
            && p.get().first_child == Some(src)
        {
            p.get().first_child = Some(dest);
        }
        if let Some(prev) = d.prev {
            prev.get().next = Some(dest);
        }
        if let Some(next) = d.next {
            next.get().prev = Some(dest);
        }
        let mut child = d.first_child;
        while let Some(c) = child {
            c.get().parent = Some(dest);
            child = c.get().next;
        }
    }
}

/// Takes `slot` out of the tree; its children move to its parent.
fn unlink(slot: KPtr<Slot>) {
    // SAFETY: see above.
    unsafe {
        let s = slot.get();
        let (parent, prev, next, mut child) = (s.parent, s.prev, s.next, s.first_child);
        match prev {
            Some(p) => p.get().next = next,
            None => {
                if let Some(p) = parent {
                    p.get().first_child = next;
                }
            }
        }
        if let Some(n) = next {
            n.get().prev = prev;
        }
        while let Some(c) = child {
            let following = c.get().next;
            let cs = c.get();
            cs.prev = None;
            cs.next = None;
            cs.parent = None;
            if let Some(p) = parent {
                let first = p.get().first_child;
                cs.parent = Some(p);
                cs.next = first;
                if let Some(f) = first {
                    f.get().prev = Some(c);
                }
                p.get().first_child = Some(c);
            }
            child = following;
        }
        *slot.get() = Slot::EMPTY;
    }
}

/// Deletes the capability in `slot`. The last capability to an object destroys it.
pub fn delete(k: &mut Kernel, slot: KPtr<Slot>) {
    // SAFETY: see above.
    let cap = unsafe { slot.get() }.cap;
    if cap == Cap::Null {
        return;
    }
    unlink(slot);
    release(k, cap);
}

/// Deletes every capability derived from `slot`. Revoking an Untyped also makes all of its
/// memory free again.
pub fn revoke(k: &mut Kernel, slot: KPtr<Slot>) {
    // Always restart from `slot`: deleting one capability may destroy objects holding others.
    // SAFETY: see above.
    while let Some(mut leaf) = unsafe { slot.get() }.first_child {
        // SAFETY: see above.
        while let Some(c) = unsafe { leaf.get() }.first_child {
            leaf = c;
        }
        delete(k, leaf);
    }
    // SAFETY: see above.
    if let Cap::Untyped { free, .. } = &mut unsafe { slot.get() }.cap {
        *free = 0;
    }
}

fn release(k: &mut Kernel, cap: Cap) {
    // SAFETY: see above.
    unsafe {
        match cap {
            Cap::Frame { mapped: Some(m), .. } | Cap::Device { mapped: Some(m), .. } => k.spaces.unmap(m),
            Cap::Endpoint { ep, .. } => {
                let e = ep.get();
                e.refs -= 1;
                if e.refs == 0 {
                    crate::ipc::destroy_endpoint(k, ep);
                }
            }
            Cap::Notification { ntfn, .. } => {
                let n = ntfn.get();
                n.refs -= 1;
                if n.refs == 0 {
                    crate::ipc::destroy_notification(k, ntfn);
                }
            }
            Cap::Thread(t) => {
                let th = t.get();
                th.refs -= 1;
                if th.refs == 0 {
                    k.destroy_thread(t);
                }
            }
            Cap::AddressSpace(a) => {
                let s = a.get();
                s.refs -= 1;
                if s.refs == 0 {
                    k.spaces.destroy(a);
                }
            }
            Cap::CNode(c) => {
                c.get().refs -= 1;
                if c.get().refs == 0 {
                    for i in 0..CNODE_SLOTS {
                        if let Some(s) = c.get().slot(i) {
                            delete(k, s);
                        }
                    }
                }
            }
            Cap::Irq { index } => crate::irq::unbind(index as usize),
            Cap::Null
            | Cap::Untyped { .. }
            | Cap::Frame { mapped: None, .. }
            | Cap::Device { mapped: None, .. }
            | Cap::Debug => {}
        }
    }
}
