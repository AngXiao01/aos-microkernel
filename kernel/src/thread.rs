//! Threads (TCBs) and the intrusive queues they wait in.

use crate::arch::user::{FpState, SPSR_EL0, UserContext};
use crate::cap::{CNode, Cap, Slot};
use crate::ipc::{Endpoint, Notification};
use crate::kobj::KPtr;
use crate::vspace::AddressSpace;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    BlockedSend,
    BlockedRecv,
    /// Called an endpoint; the message was taken and the reply is outstanding.
    BlockedReply,
    BlockedWait,
    /// Exited, faulted or suspended: never scheduled again.
    Inactive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocked {
    Nothing,
    Endpoint(KPtr<Endpoint>),
    Notification(KPtr<Notification>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Code(u64),
    Fault { vector: u64, esr: u64, far: u64, elr: u64 },
}

/// Links for one intrusive queue.
#[derive(Clone, Copy, Debug, Default)]
pub struct Links {
    pub next: Option<KPtr<Thread>>,
    pub prev: Option<KPtr<Thread>>,
}

pub struct Thread {
    pub ctx: UserContext,
    pub fp: FpState,
    /// Capabilities naming this thread.
    pub refs: u32,
    pub id: u32,
    pub state: ThreadState,
    /// 0 (lowest) to 255.
    pub priority: u8,
    /// Ticks left before round-robin preemption.
    pub timeslice: u32,
    /// The thread's capability space, address space and IPC buffer frame: capabilities,
    /// children of those the thread was configured from.
    pub cspace_slot: Slot,
    pub vspace_slot: Slot,
    pub ipc_slot: Slot,
    /// Ready queue, endpoint queue or notification queue: at most one at a time.
    pub queue: Links,
    /// The timeout list.
    pub timer: Links,
    /// The kernel's list of all threads (capability audit, reply validation).
    pub all: Links,
    /// Counter value at which a blocking call times out.
    pub deadline: Option<u64>,
    pub blocked_on: Blocked,
    /// While blocked sending: the badge and rights of the capability used, and whether it
    /// is a call.
    pub send_badge: u64,
    pub send_grant: bool,
    pub send_is_call: bool,
    /// The caller this thread owes a reply, with the caller's reply token at the time.
    pub caller: Option<(KPtr<Thread>, u64)>,
    /// Unique per wait for a reply, so that a reply meant for an earlier, timed-out call is
    /// not delivered to a later one.
    pub reply_token: u64,
    pub exit: Option<Exit>,
}

pub const TIMESLICE_TICKS: u32 = 10;

/// Where a new thread starts.
#[derive(Clone, Copy, Debug)]
pub struct Start {
    pub entry: u64,
    pub stack_top: u64,
    /// x0 and x1.
    pub args: [u64; 2],
}

impl Thread {
    /// An inactive thread with no address space, capability space or IPC buffer.
    pub fn new(id: u32) -> Thread {
        Thread {
            ctx: UserContext { x: [0; 31], sp_el0: 0, elr: 0, spsr: SPSR_EL0 },
            fp: FpState::ZERO,
            refs: 0,
            id,
            state: ThreadState::Inactive,
            priority: 0,
            timeslice: TIMESLICE_TICKS,
            cspace_slot: Slot::EMPTY,
            vspace_slot: Slot::EMPTY,
            ipc_slot: Slot::EMPTY,
            queue: Links::default(),
            timer: Links::default(),
            all: Links::default(),
            deadline: None,
            blocked_on: Blocked::Nothing,
            send_badge: 0,
            send_grant: false,
            send_is_call: false,
            caller: None,
            reply_token: 0,
            exit: None,
        }
    }

    pub fn set_start(&mut self, start: Start) {
        self.ctx = UserContext { x: [0; 31], sp_el0: start.stack_top, elr: start.entry, spsr: SPSR_EL0 };
        self.ctx.x[0] = start.args[0];
        self.ctx.x[1] = start.args[1];
    }

    pub fn cnode(&self) -> Option<KPtr<CNode>> {
        match self.cspace_slot.cap {
            Cap::CNode(c) => Some(c),
            _ => None,
        }
    }

    pub fn space(&self) -> Option<KPtr<AddressSpace>> {
        match self.vspace_slot.cap {
            Cap::AddressSpace(a) => Some(a),
            _ => None,
        }
    }

    /// Physical address of the IPC buffer frame.
    pub fn ipc_buffer(&self) -> Option<usize> {
        match self.ipc_slot.cap {
            Cap::Frame { pa, .. } => Some(pa),
            _ => None,
        }
    }

    /// Sets the status register (x0) a system call returns.
    pub fn set_status(&mut self, error: aos_abi::Error) {
        self.ctx.x[0] = error as u64;
    }
}

pub type LinkOf = fn(&mut Thread) -> &mut Links;

pub fn queue_link(t: &mut Thread) -> &mut Links {
    &mut t.queue
}

pub fn timer_link(t: &mut Thread) -> &mut Links {
    &mut t.timer
}

pub fn all_link(t: &mut Thread) -> &mut Links {
    &mut t.all
}

/// A doubly linked FIFO of threads threaded through one of their `Links`.
#[derive(Clone, Copy, Debug)]
pub struct Queue {
    head: Option<KPtr<Thread>>,
    tail: Option<KPtr<Thread>>,
}

// SAFETY (for all methods): threads in a queue are distinct live kernel objects, and the
// kernel holds no other reference to them while the queue is manipulated.
impl Queue {
    pub const EMPTY: Queue = Queue { head: None, tail: None };

    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    pub fn front(&self) -> Option<KPtr<Thread>> {
        self.head
    }

    pub fn push_back(&mut self, t: KPtr<Thread>, link: LinkOf) {
        // SAFETY: see impl.
        unsafe {
            *link(t.get()) = Links { next: None, prev: self.tail };
            match self.tail {
                Some(tail) => link(tail.get()).next = Some(t),
                None => self.head = Some(t),
            }
        }
        self.tail = Some(t);
    }

    pub fn push_front(&mut self, t: KPtr<Thread>, link: LinkOf) {
        // SAFETY: see impl.
        unsafe {
            *link(t.get()) = Links { next: self.head, prev: None };
            match self.head {
                Some(head) => link(head.get()).prev = Some(t),
                None => self.tail = Some(t),
            }
        }
        self.head = Some(t);
    }

    /// Inserts before the first thread for which `before(existing)` holds.
    pub fn insert_by(&mut self, t: KPtr<Thread>, link: LinkOf, before: impl Fn(&Thread) -> bool) {
        let mut at = self.head;
        // SAFETY: see impl.
        unsafe {
            while let Some(cur) = at {
                if before(cur.get()) {
                    let prev = link(cur.get()).prev;
                    *link(t.get()) = Links { next: Some(cur), prev };
                    link(cur.get()).prev = Some(t);
                    match prev {
                        Some(p) => link(p.get()).next = Some(t),
                        None => self.head = Some(t),
                    }
                    return;
                }
                at = link(cur.get()).next;
            }
        }
        self.push_back(t, link);
    }

    pub fn pop_front(&mut self, link: LinkOf) -> Option<KPtr<Thread>> {
        let t = self.head?;
        self.remove(t, link);
        Some(t)
    }

    /// Every thread in the queue, front to back.
    pub fn iter(&self, link: LinkOf) -> QueueIter {
        QueueIter { next: self.head, link }
    }

    /// Removes `t`, which must be in this queue.
    pub fn remove(&mut self, t: KPtr<Thread>, link: LinkOf) {
        // SAFETY: see impl.
        unsafe {
            let Links { next, prev } = *link(t.get());
            match prev {
                Some(p) => link(p.get()).next = next,
                None => self.head = next,
            }
            match next {
                Some(n) => link(n.get()).prev = prev,
                None => self.tail = prev,
            }
            *link(t.get()) = Links::default();
        }
    }
}

pub struct QueueIter {
    next: Option<KPtr<Thread>>,
    link: LinkOf,
}

impl Iterator for QueueIter {
    type Item = KPtr<Thread>;

    fn next(&mut self) -> Option<KPtr<Thread>> {
        let t = self.next?;
        // SAFETY: queued threads are live; the reference ends here.
        self.next = (self.link)(unsafe { t.get() }).next;
        Some(t)
    }
}
