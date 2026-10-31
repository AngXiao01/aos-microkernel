//! B-2 capability unit tests: retype, copy/mint attenuation, the derivation tree, object
//! destruction, revocation of Untyped memory and frame mappings. The tests drive the
//! object methods directly with a CNode of their own and an Untyped carved from the boot
//! allocator.

use aos_abi::{Error, ktest::*, method, object, rights};

use crate::arch::timer;
use crate::cap::{self, CNode, Cap, Rights};
use crate::invoke::dispatch;
use crate::kobj::KPtr;
use crate::mm::paging::translate;
use crate::sched::{KERNEL, Kernel};
use crate::thread::{Exit, ThreadState};

const SELF: u64 = 1;
const UNTYPED: u64 = 2;
const UNTYPED_BITS: u8 = 20;

struct Setup {
    cnode: KPtr<CNode>,
    base: usize,
}

/// A CNode holding a capability to itself in slot 1 and a fresh 1 MiB Untyped in slot 2.
fn setup() -> Setup {
    // SAFETY: zeroed memory is an empty CNode.
    let cnode = unsafe { KPtr::<CNode>::zeroed() }.expect("cnode");
    let base =
        crate::mm::with_frames(|f| f.alloc_region(1 << UNTYPED_BITS, 1 << UNTYPED_BITS)).expect("untyped memory");
    cap::insert(slot(cnode, SELF), Cap::CNode(cnode), None);
    cap::insert(slot(cnode, UNTYPED), Cap::Untyped { base, size_bits: UNTYPED_BITS, free: 0 }, None);
    Setup { cnode, base }
}

fn slot(cnode: KPtr<CNode>, i: u64) -> KPtr<cap::Slot> {
    // SAFETY: test-owned CNode; no other reference is live.
    unsafe { cnode.get() }.slot(i).expect("in range")
}

fn get(cnode: KPtr<CNode>, i: u64) -> Cap {
    // SAFETY: as above.
    unsafe { cnode.get() }.get(i)
}

fn call(k: &mut Kernel, s: &Setup, target: u64, m: u64, args: [u64; 4]) -> Result<[u64; 4], Error> {
    dispatch(k, s.cnode, 255, target, m, args)
}

fn object_pa(c: Cap) -> usize {
    match c {
        Cap::Endpoint { ep, .. } => ep.pa(),
        Cap::Thread(t) => t.pa(),
        Cap::CNode(c) => c.pa(),
        Cap::Frame { pa, .. } => pa,
        Cap::AddressSpace(a) => a.pa(),
        other => panic!("no object behind {other:?}"),
    }
}

ktest! {
    fn retype_carves_aligned_objects_within_bounds() {
        let mut k = KERNEL.lock();
        let s = setup();
        kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::ENDPOINT, 10, 3, 0]));
        for i in 0..3 {
            kassert_eq!(object_pa(get(s.cnode, 10 + i)), s.base + 64 * i as usize);
        }
        kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::FRAME, 13, 1, 0]));
        kassert_eq!(object_pa(get(s.cnode, 13)), s.base + 4096, "aligned past the endpoints");
        kassert_eq!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::FRAME, 13, 1, 0]), Err(Error::SlotInUse));
        kassert_eq!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::ADDRESS_SPACE, 20, 16, 0]), Err(Error::NoMemory));
        kassert_eq!(call(&mut k, &s, UNTYPED, method::RETYPE, [99, 20, 1, 0]), Err(Error::InvalidArgument));
        // Failed calls made nothing: the next frame still follows the first.
        kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::FRAME, 14, 1, 0]));
        kassert_eq!(object_pa(get(s.cnode, 14)), s.base + 2 * 4096);
        kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::CNODE, 15, 1, 0]));
        kassert_eq!(object_pa(get(s.cnode, 15)), s.base + 32 * 1024, "CNodes are 32 KiB aligned");
    }

    fn copies_and_mints_only_attenuate() {
        let mut k = KERNEL.lock();
        let s = setup();
        kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::ENDPOINT, 10, 1, 0]));
        kunwrap!(call(&mut k, &s, SELF, method::MINT, [10, 11, rights::SEND, 5]));
        kunwrap!(call(&mut k, &s, SELF, method::MINT, [11, 12, rights::ALL, 9]));
        match (get(s.cnode, 11), get(s.cnode, 12)) {
            (Cap::Endpoint { badge: 5, rights: r1, .. }, Cap::Endpoint { badge: 5, rights: r2, .. }) => {
                kassert_eq!(r1, Rights::SEND);
                kassert_eq!(r2, Rights::SEND, "a copy never gains rights");
            }
            other => kfail!("unexpected {other:?}"),
        }
        kassert_eq!(call(&mut k, &s, SELF, method::COPY, [UNTYPED, 13, rights::ALL, 0]), Err(Error::InvalidArgument), "Untyped is never copied");
        kassert_eq!(call(&mut k, &s, SELF, method::COPY, [10, 12, rights::ALL, 0]), Err(Error::SlotInUse));
    }

    fn delete_hands_children_to_the_parent_and_revoke_removes_descendants() {
        let mut k = KERNEL.lock();
        let s = setup();
        kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::ENDPOINT, 10, 1, 0]));
        kunwrap!(call(&mut k, &s, SELF, method::COPY, [10, 11, rights::ALL, 0]));
        kunwrap!(call(&mut k, &s, SELF, method::COPY, [11, 12, rights::ALL, 0]));
        kunwrap!(call(&mut k, &s, SELF, method::DELETE, [11, 0, 0, 0]));
        kassert!(get(s.cnode, 12) != Cap::Null, "the grandchild survives its parent");
        kunwrap!(call(&mut k, &s, SELF, method::REVOKE, [10, 0, 0, 0]));
        kassert_eq!(get(s.cnode, 12), Cap::Null, "…and is now a child of slot 10, so revoke removes it");
        kassert!(get(s.cnode, 10) != Cap::Null, "revoke keeps the capability itself");
        kunwrap!(call(&mut k, &s, SELF, method::MOVE, [10, 20, 0, 0]));
        kassert_eq!(get(s.cnode, 10), Cap::Null);
        kunwrap!(call(&mut k, &s, SELF, method::COPY, [20, 21, rights::ALL, 0]));
        kunwrap!(call(&mut k, &s, SELF, method::REVOKE, [20, 0, 0, 0]));
        kassert_eq!(get(s.cnode, 21), Cap::Null, "a moved capability keeps its children");
    }

    fn the_last_capability_destroys_the_object_and_fails_its_waiters() {
        let mut k = KERNEL.lock();
        let s = setup();
        kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::ENDPOINT, 10, 1, 0]));
        let Cap::Endpoint { ep, .. } = get(s.cnode, 10) else { kfail!("no endpoint") };
        let t = crate::process::spawn(&mut k, crate::user_tests::IMAGE, 10, [FIFO_RECEIVER, 1]).expect("spawn");
        // SAFETY: test setup.
        let theirs = unsafe { t.get().cnode().expect("bound").get().slot(SLOT_ENDPOINT).expect("slot") };
        cap::insert(theirs, Cap::Endpoint { ep, badge: 0, rights: Rights::RECV }, Some(slot(s.cnode, 10)));
        let give_up = timer::now() + 5 * timer::frequency();
        // SAFETY (closures): called between traps.
        kassert!(k.run_until(|_| unsafe { t.get() }.state == ThreadState::BlockedRecv, give_up));
        kassert_eq!(unsafe { ep.get() }.refs, 2);
        kunwrap!(call(&mut k, &s, SELF, method::DELETE, [10, 0, 0, 0]));
        kassert_eq!(unsafe { t.get() }.state, ThreadState::BlockedRecv, "one capability is left");
        cap::delete(&mut k, theirs);
        kassert!(k.run_until(|_| unsafe { t.get() }.state == ThreadState::Inactive, give_up));
        kassert_eq!(unsafe { t.get() }.exit, Some(Exit::Code(0xbad)), "the receive failed");
    }

    fn revoking_untyped_destroys_everything_made_from_it() {
        let mut k = KERNEL.lock();
        let s = setup();
        let asids = k.spaces.free_asids();
        for (kind, at) in [(object::CNODE, 10), (object::ADDRESS_SPACE, 11), (object::THREAD, 12), (object::ENDPOINT, 13), (object::FRAME, 14)] {
            kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [kind, at, 1, 0]));
        }
        kassert_eq!(k.spaces.free_asids(), asids - 1);
        let first = object_pa(get(s.cnode, 10));
        // Capabilities inside the nested CNode, derived from objects of the same Untyped.
        kunwrap!(call(&mut k, &s, 10, method::COPY, [13, 1, rights::ALL, 0]));
        kunwrap!(call(&mut k, &s, 10, method::COPY, [12, 2, rights::ALL, 0]));
        kunwrap!(call(&mut k, &s, SELF, method::REVOKE, [UNTYPED, 0, 0, 0]));
        for i in 10..15 {
            kassert_eq!(get(s.cnode, i), Cap::Null, "slot {i} survived the revoke");
        }
        kassert_eq!(k.spaces.free_asids(), asids, "the address space released its ASID");
        kassert!(matches!(get(s.cnode, UNTYPED), Cap::Untyped { free: 0, .. }), "all memory is free again");
        kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::CNODE, 10, 1, 0]));
        kassert_eq!(object_pa(get(s.cnode, 10)), first, "the memory is reused");
    }

    fn frames_map_once_and_unmap_when_deleted() {
        let mut k = KERNEL.lock();
        let s = setup();
        kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::ADDRESS_SPACE, 10, 1, 0]));
        kunwrap!(call(&mut k, &s, UNTYPED, method::RETYPE, [object::FRAME, 11, 2, 0]));
        let Cap::AddressSpace(space) = get(s.cnode, 10) else { kfail!("no space") };
        let va = 0x1000_0000u64;
        kunwrap!(call(&mut k, &s, 10, method::MAP, [11, va, method::WRITE, 0]));
        // SAFETY: test-owned address space.
        let root = unsafe { space.get() }.root;
        kassert_eq!(translate(root, va as usize).map(|(pa, _)| pa), Some(object_pa(get(s.cnode, 11))));
        kassert_eq!(call(&mut k, &s, 10, method::MAP, [11, va + 0x1000, 0, 0]), Err(Error::AlreadyMapped), "a frame maps once");
        kassert_eq!(call(&mut k, &s, 10, method::MAP, [12, va, 0, 0]), Err(Error::AlreadyMapped), "an address maps once");
        kassert_eq!(call(&mut k, &s, 10, method::MAP, [12, va + 0x1000, method::WRITE | method::EXECUTE, 0]), Err(Error::InvalidArgument), "W^X");
        kassert_eq!(call(&mut k, &s, 10, method::MAP, [12, 0xffff_0000_0000_0000, 0, 0]), Err(Error::InvalidArgument));
        kunwrap!(call(&mut k, &s, SELF, method::DELETE, [11, 0, 0, 0]));
        kassert_eq!(translate(root, va as usize), None, "deleting the frame capability unmaps it");
        kunwrap!(call(&mut k, &s, SELF, method::MINT, [12, 13, 0, 0]));
        kassert_eq!(call(&mut k, &s, 10, method::MAP, [13, va, method::WRITE, 0]), Err(Error::NoRight), "a read-only copy");
    }
}
