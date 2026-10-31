//! Synchronous IPC through endpoints and asynchronous signals through notifications
//! (§B3.1).
//!
//! An endpoint is a rendezvous: whichever side arrives first waits in the endpoint's FIFO
//! queue. A call additionally blocks the caller until the receiver replies; the receiver
//! remembers whom it owes a reply (one at a time). Messages are copied between the threads'
//! registers and, beyond `MSG_REGS` words, between their IPC buffer frames, which the
//! kernel reaches through the linear map, so no user pointer is ever dereferenced.

use core::ptr;

use aos_abi::{Error, IpcBuffer, MAX_MSG_CAPS, MAX_MSG_WORDS, MSG_REGS, MsgInfo, rights};

use crate::cap::{self, Cap, Rights};
use crate::kobj::KPtr;
use crate::mm::phys_to_virt;
use crate::sched::Kernel;
use crate::thread::{Blocked, Queue, Thread, ThreadState, queue_link};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EpState {
    Idle,
    /// The queue holds blocked senders.
    Senders,
    /// The queue holds blocked receivers.
    Receivers,
}

pub struct Endpoint {
    /// Capabilities naming this endpoint.
    pub refs: u32,
    queue: Queue,
    state: EpState,
}

impl Endpoint {
    pub const fn new() -> Endpoint {
        Endpoint { refs: 0, queue: Queue::EMPTY, state: EpState::Idle }
    }

    /// Takes `t` out of this endpoint's queue (timeout, suspension).
    pub fn remove(&mut self, t: KPtr<Thread>) {
        self.queue.remove(t, queue_link);
        if self.queue.is_empty() {
            self.state = EpState::Idle;
        }
    }

    fn pop(&mut self) -> Option<KPtr<Thread>> {
        let t = self.queue.pop_front(queue_link);
        if self.queue.is_empty() {
            self.state = EpState::Idle;
        }
        t
    }
}

pub struct Notification {
    pub refs: u32,
    bits: u64,
    waiters: Queue,
}

impl Notification {
    pub const fn new() -> Notification {
        Notification { refs: 0, bits: 0, waiters: Queue::EMPTY }
    }

    pub fn remove(&mut self, t: KPtr<Thread>) {
        self.waiters.remove(t, queue_link);
    }
}

// SAFETY (for the `get` calls below): the kernel is single-threaded; each function holds
// at most one reference per thread or object, and the threads involved in one transfer
// are distinct (a thread cannot be blocked and running at once).

fn regs(t: KPtr<Thread>) -> (u64, MsgInfo, u64) {
    // SAFETY: see above.
    let th = unsafe { t.get() };
    (th.ctx.x[0], MsgInfo(th.ctx.x[1]), th.ctx.x[6])
}

fn status(t: KPtr<Thread>, e: Error) {
    // SAFETY: see above.
    unsafe { t.get() }.set_status(e);
}

pub fn lookup(t: KPtr<Thread>, slot: u64) -> Cap {
    // SAFETY: see above.
    unsafe { t.get().cnode().map_or(Cap::Null, |c| c.get().get(slot)) }
}

fn buffer(pa: usize) -> *mut IpcBuffer {
    phys_to_virt(pa) as *mut IpcBuffer
}

/// Copies the capabilities `src` sends into `dst`'s receive slots; returns how many arrived.
/// Capabilities that cannot be copied (Untyped) and full or missing slots end the transfer.
fn transfer_caps(src: KPtr<Thread>, dst: KPtr<Thread>, count: usize) -> usize {
    // SAFETY: see above; the threads are distinct and we only read their bindings.
    let (src_cnode, dst_cnode, src_buf, dst_buf) = unsafe {
        let (s, d) = (src.get(), dst.get());
        match (s.cnode(), d.cnode(), s.ipc_buffer(), d.ipc_buffer()) {
            (Some(a), Some(b), Some(c), Some(e)) => (a, b, c, e),
            _ => return 0,
        }
    };
    // SAFETY: IPC buffer frames belong to the kernel and are mapped in the linear map.
    let (slots, first) = unsafe { ((*buffer(src_buf)).caps, (*buffer(dst_buf)).recv_slot) };
    if first == 0 {
        return 0;
    }
    let mut received = 0;
    for &from in slots.iter().take(count.min(MAX_MSG_CAPS)) {
        // SAFETY: see above; source and destination slots are distinct (the destination is
        // empty, the source is not).
        let (from_slot, cap, to_slot) = unsafe {
            let Some(from_slot) = src_cnode.get().slot(from) else { break };
            let Some(cap) = cap::derive(from_slot.get().cap, rights::ALL, None) else { break };
            let Some(to_slot) = dst_cnode.get().slot(first + received as u64) else { break };
            if to_slot.get().cap != Cap::Null {
                break;
            }
            (from_slot, cap, to_slot)
        };
        cap::insert(to_slot, cap, Some(from_slot));
        received += 1;
    }
    received
}

/// Copies the message `src` is sending into `dst`'s registers and IPC buffer, and the
/// capabilities it carries if `grant` allows.
fn transfer(src: KPtr<Thread>, dst: KPtr<Thread>, badge: u64, grant: bool) {
    debug_assert!(src != dst);
    let caps = MsgInfo(unsafe { src.get() }.ctx.x[1]).caps();
    let received = if grant && caps > 0 { transfer_caps(src, dst, caps) } else { 0 };
    // SAFETY: see above; `src != dst`.
    let (s, d) = unsafe { (src.get(), dst.get()) };
    let info = MsgInfo(s.ctx.x[1]);
    let buffers = s.ipc_buffer().zip(d.ipc_buffer());
    let len = if buffers.is_some() { info.len() } else { info.len().min(MSG_REGS) };
    d.ctx.x[1] = MsgInfo::new(info.label(), len).with_caps(received).0;
    d.ctx.x[2..2 + MSG_REGS].copy_from_slice(&s.ctx.x[2..2 + MSG_REGS]);
    d.ctx.x[6] = badge;
    if let Some((sp, dp)) = buffers
        && len > MSG_REGS
    {
        let from = phys_to_virt(sp) as *const IpcBuffer;
        let to = phys_to_virt(dp) as *mut IpcBuffer;
        // SAFETY: both are IPC buffer frames owned by the kernel and mapped in the linear
        // map; `len <= MAX_MSG_WORDS` was checked when the message was sent. `ptr::copy`
        // tolerates a buffer shared by mistake.
        unsafe {
            ptr::copy(
                (&raw const (*from).msg).cast::<u64>().add(MSG_REGS),
                (&raw mut (*to).msg).cast::<u64>().add(MSG_REGS),
                len - MSG_REGS,
            );
        }
    }
}

/// Puts `caller`, whose message `server` has taken, to sleep until `server` replies.
fn await_reply(k: &mut Kernel, caller: KPtr<Thread>, server: KPtr<Thread>) {
    // SAFETY: see above; caller and server are distinct.
    let (c, s) = unsafe { (caller.get(), server.get()) };
    c.reply_token = k.next_reply_token();
    c.state = ThreadState::BlockedReply;
    c.blocked_on = Blocked::Nothing;
    s.caller = Some((caller, c.reply_token));
    k.leave_cpu(caller);
}

/// SEND and CALL.
pub fn send(k: &mut Kernel, t: KPtr<Thread>, is_call: bool) {
    let (slot, info, timeout) = regs(t);
    if info.len() > MAX_MSG_WORDS {
        return status(t, Error::InvalidArgument);
    }
    let Cap::Endpoint { ep, badge, rights } = lookup(t, slot) else { return status(t, Error::InvalidCap) };
    if !rights.contains(Rights::SEND) {
        return status(t, Error::NoRight);
    }
    // SAFETY: see above.
    let e = unsafe { ep.get() };
    let grant = rights.contains(Rights::GRANT);
    if e.state == EpState::Receivers {
        let r = e.pop().expect("receivers queued");
        k.cancel_timeout(r);
        transfer(t, r, badge, grant);
        status(r, Error::Ok);
        // SAFETY: see above.
        unsafe { r.get() }.blocked_on = Blocked::Nothing;
        if is_call {
            k.set_timeout(t, timeout);
            await_reply(k, t, r);
        } else {
            status(t, Error::Ok);
        }
        k.make_ready(r);
    } else {
        // SAFETY: see above.
        let th = unsafe { t.get() };
        th.send_badge = badge;
        th.send_grant = grant;
        th.send_is_call = is_call;
        th.state = ThreadState::BlockedSend;
        th.blocked_on = Blocked::Endpoint(ep);
        e.queue.push_back(t, queue_link);
        e.state = EpState::Senders;
        k.set_timeout(t, timeout);
        k.leave_cpu(t);
    }
}

/// RECV.
pub fn recv(k: &mut Kernel, t: KPtr<Thread>) {
    let (slot, _, timeout) = regs(t);
    let Cap::Endpoint { ep, rights, .. } = lookup(t, slot) else { return status(t, Error::InvalidCap) };
    if !rights.contains(Rights::RECV) {
        return status(t, Error::NoRight);
    }
    // SAFETY: see above.
    let e = unsafe { ep.get() };
    if e.state == EpState::Senders {
        let s = e.pop().expect("senders queued");
        // SAFETY: see above.
        let (badge, grant, is_call) = {
            let st = unsafe { s.get() };
            st.blocked_on = Blocked::Nothing;
            (st.send_badge, st.send_grant, st.send_is_call)
        };
        transfer(s, t, badge, grant);
        status(t, Error::Ok);
        if is_call {
            await_reply(k, s, t); // the caller's deadline, if any, now covers the reply
        } else {
            k.cancel_timeout(s);
            status(s, Error::Ok);
            k.make_ready(s);
        }
    } else {
        // SAFETY: see above.
        let th = unsafe { t.get() };
        th.state = ThreadState::BlockedRecv;
        th.blocked_on = Blocked::Endpoint(ep);
        e.queue.push_back(t, queue_link);
        e.state = EpState::Receivers;
        k.set_timeout(t, timeout);
        k.leave_cpu(t);
    }
}

/// REPLY: delivers `t`'s message to the caller it owes a reply.
pub fn reply(k: &mut Kernel, t: KPtr<Thread>) -> Error {
    let (_, info, _) = regs(t);
    if info.len() > MAX_MSG_WORDS {
        return Error::InvalidArgument;
    }
    // SAFETY: see above.
    let Some((caller, token)) = unsafe { t.get() }.caller.take() else { return Error::NoReply };
    // The caller may have been destroyed since: only trust it if it is still a live thread.
    if !k.is_live(caller) {
        return Error::NoReply;
    }
    // SAFETY: see above; the caller is blocked, so it is not `t`.
    let waiting = {
        let c = unsafe { caller.get() };
        c.state == ThreadState::BlockedReply && c.reply_token == token
    };
    if !waiting {
        return Error::NoReply; // the call timed out
    }
    // A reply may always carry capabilities: the caller asked for it.
    transfer(t, caller, 0, true);
    status(caller, Error::Ok);
    k.cancel_timeout(caller);
    k.make_ready(caller);
    Error::Ok
}

/// SIGNAL.
pub fn signal(k: &mut Kernel, t: KPtr<Thread>) {
    let (slot, _, _) = regs(t);
    let Cap::Notification { ntfn, badge, rights } = lookup(t, slot) else { return status(t, Error::InvalidCap) };
    if !rights.contains(Rights::SEND) {
        return status(t, Error::NoRight);
    }
    // SAFETY: see above.
    let n = unsafe { ntfn.get() };
    n.bits |= if badge == 0 { 1 } else { badge };
    if let Some(w) = n.waiters.pop_front(queue_link) {
        // SAFETY: see above; the waiter is blocked, so it is not `t`.
        let wt = unsafe { w.get() };
        wt.ctx.x[2] = core::mem::take(&mut n.bits);
        wt.blocked_on = Blocked::Nothing;
        wt.set_status(Error::Ok);
        k.cancel_timeout(w);
        k.make_ready(w);
    }
    status(t, Error::Ok);
}

/// WAIT: returns and clears the pending bits, blocking while there are none.
pub fn wait(k: &mut Kernel, t: KPtr<Thread>) {
    let (slot, _, timeout) = regs(t);
    let Cap::Notification { ntfn, rights, .. } = lookup(t, slot) else { return status(t, Error::InvalidCap) };
    if !rights.contains(Rights::RECV) {
        return status(t, Error::NoRight);
    }
    // SAFETY: see above.
    let (n, th) = unsafe { (ntfn.get(), t.get()) };
    if n.bits != 0 {
        th.ctx.x[2] = core::mem::take(&mut n.bits);
        th.set_status(Error::Ok);
    } else {
        th.state = ThreadState::BlockedWait;
        th.blocked_on = Blocked::Notification(ntfn);
        n.waiters.push_back(t, queue_link);
        k.set_timeout(t, timeout);
        k.leave_cpu(t);
    }
}

/// The last capability to an endpoint is gone: its waiters fail with `InvalidCap`.
pub fn destroy_endpoint(k: &mut Kernel, ep: KPtr<Endpoint>) {
    // SAFETY: see above.
    while let Some(t) = unsafe { ep.get() }.pop() {
        wake_failed(k, t);
    }
}

pub fn destroy_notification(k: &mut Kernel, ntfn: KPtr<Notification>) {
    // SAFETY: see above.
    while let Some(t) = unsafe { ntfn.get() }.waiters.pop_front(queue_link) {
        wake_failed(k, t);
    }
}

fn wake_failed(k: &mut Kernel, t: KPtr<Thread>) {
    k.cancel_timeout(t);
    // SAFETY: see above.
    let th = unsafe { t.get() };
    th.blocked_on = Blocked::Nothing;
    th.set_status(Error::InvalidCap);
    k.make_ready(t);
}
