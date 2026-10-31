//! Capabilities and capability spaces.
//!
//! B-1 has only the capabilities IPC needs, held in a fixed-size CNode per thread; user
//! space names a capability by its slot index (CPtr). Derivation, revocation and the
//! other object types arrive with the capability system in B-2.

use crate::ipc::{Endpoint, Notification};
use crate::kobj::KPtr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(u8);

impl Rights {
    pub const SEND: Rights = Rights(1);
    pub const RECV: Rights = Rights(2);
    pub const ALL: Rights = Rights(3);

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    Null,
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
}

pub const CNODE_SLOTS: usize = 64;

pub struct CNode {
    slots: [Cap; CNODE_SLOTS],
}

impl CNode {
    pub const fn new() -> CNode {
        CNode { slots: [Cap::Null; CNODE_SLOTS] }
    }

    /// The capability in `slot`; `Null` for out-of-range slots.
    pub fn get(&self, slot: u64) -> Cap {
        usize::try_from(slot).ok().and_then(|i| self.slots.get(i)).copied().unwrap_or(Cap::Null)
    }

    pub fn set(&mut self, slot: usize, cap: Cap) {
        self.slots[slot] = cap;
    }
}
