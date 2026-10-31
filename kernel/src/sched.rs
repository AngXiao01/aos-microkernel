//! The scheduler and the kernel's run loop (§B3.1): fixed priorities 0–255, round robin
//! within a priority, preemption by the timer tick and by higher-priority wakeups.
//!
//! The run loop is the only place kernel state changes: it picks a thread, runs it until
//! it traps (`arch::user::enter`), and handles the trap. Interrupt handlers only record
//! events (`irq`), which the loop then processes, so one `&mut Kernel` suffices.

use crate::arch::exception::{EL0_IRQ, EL0_SYNC, ec, exception_class};
use crate::arch::{cpu, timer, user};
use crate::cap;
use crate::irq;
use crate::kobj::KPtr;
use crate::sync::SpinLock;
use crate::syscall;
use crate::thread::{Blocked, Exit, Queue, TIMESLICE_TICKS, Thread, ThreadState, all_link, queue_link, timer_link};
use crate::vspace::Spaces;

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    /// Times a different thread than the last one was entered.
    pub switches: u64,
    /// Times a thread was taken off the CPU while still runnable.
    pub preemptions: u64,
    pub syscalls: u64,
    pub ticks: u64,
}

pub struct Kernel {
    ready: [Queue; 256],
    /// Bit p set iff `ready[p]` is non-empty.
    bitmap: [u64; 4],
    current: Option<KPtr<Thread>>,
    /// Blocked threads with a deadline, earliest first.
    timers: Queue,
    /// The thread whose FP/SIMD state is in the registers.
    fp_owner: Option<KPtr<Thread>>,
    last_run: Option<KPtr<Thread>>,
    /// Every thread object that exists.
    threads: Queue,
    pub spaces: Spaces,
    pub stats: Stats,
    next_id: u32,
    next_reply_token: u64,
}

// SAFETY: there is one CPU, and kernel state is only touched from the run loop.
unsafe impl Send for Kernel {}

pub static KERNEL: SpinLock<Kernel> = SpinLock::new(Kernel::new());

// SAFETY (for the `get` calls below): see `KPtr::get`; each method holds at most one
// reference per thread at a time.
impl Kernel {
    const fn new() -> Kernel {
        Kernel {
            ready: [Queue::EMPTY; 256],
            bitmap: [0; 4],
            current: None,
            timers: Queue::EMPTY,
            fp_owner: None,
            last_run: None,
            threads: Queue::EMPTY,
            spaces: Spaces::new(),
            stats: Stats { switches: 0, preemptions: 0, syscalls: 0, ticks: 0 },
            next_id: 1,
            next_reply_token: 1,
        }
    }

    /// Records a newly created thread object and returns its id.
    pub fn register(&mut self, t: KPtr<Thread>) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        // SAFETY: see impl.
        unsafe { t.get() }.id = id;
        self.threads.push_back(t, all_link);
        id
    }

    /// Whether `t` names a thread object that still exists.
    pub fn is_live(&self, t: KPtr<Thread>) -> bool {
        self.threads.iter(all_link).any(|x| x == t)
    }

    pub fn threads(&self) -> impl Iterator<Item = KPtr<Thread>> {
        self.threads.iter(all_link)
    }

    pub fn next_reply_token(&mut self) -> u64 {
        self.next_reply_token += 1;
        self.next_reply_token
    }

    /// The last capability to `t` is gone: stop it and drop its bindings.
    pub fn destroy_thread(&mut self, t: KPtr<Thread>) {
        self.suspend(t);
        self.threads.remove(t, all_link);
        if self.fp_owner == Some(t) {
            self.fp_owner = None;
        }
        if self.last_run == Some(t) {
            self.last_run = None;
        }
        // SAFETY: see impl; the slots are inside the thread object, which stays intact until
        // its memory is retyped again (after its Untyped is revoked).
        let slots = unsafe {
            let th = t.get();
            [KPtr::from_mut(&mut th.cspace_slot), KPtr::from_mut(&mut th.vspace_slot), KPtr::from_mut(&mut th.ipc_slot)]
        };
        for slot in slots {
            cap::delete(self, slot);
        }
    }

    fn enqueue(&mut self, t: KPtr<Thread>, front: bool) {
        // SAFETY: see impl.
        let th = unsafe { t.get() };
        th.state = ThreadState::Ready;
        let p = th.priority as usize;
        if front {
            self.ready[p].push_front(t, queue_link);
        } else {
            self.ready[p].push_back(t, queue_link);
        }
        self.bitmap[p / 64] |= 1 << (p % 64);
    }

    fn dequeue(&mut self, t: KPtr<Thread>) {
        // SAFETY: see impl.
        let p = unsafe { t.get() }.priority as usize;
        self.ready[p].remove(t, queue_link);
        if self.ready[p].is_empty() {
            self.bitmap[p / 64] &= !(1 << (p % 64));
        }
    }

    /// Makes a blocked or new thread runnable; it preempts the current thread if it has a
    /// higher priority.
    pub fn make_ready(&mut self, t: KPtr<Thread>) {
        self.enqueue(t, false);
        if let Some(cur) = self.current {
            // SAFETY: see impl; `cur != t` because `t` was not running.
            let (cp, tp) = unsafe { (cur.get().priority, t.get().priority) };
            if tp > cp {
                self.current = None;
                self.enqueue(cur, true);
                self.stats.preemptions += 1;
            }
        }
    }

    fn pick(&mut self) -> Option<KPtr<Thread>> {
        if let Some(cur) = self.current {
            return Some(cur);
        }
        let word = (0..4).rev().find(|&w| self.bitmap[w] != 0)?;
        let p = word * 64 + 63 - self.bitmap[word].leading_zeros() as usize;
        let t = self.ready[p].front().expect("bitmap and queues agree");
        self.dequeue(t);
        // SAFETY: see impl.
        unsafe { t.get() }.state = ThreadState::Running;
        self.current = Some(t);
        Some(t)
    }

    /// The thread to run next, skipping (and stopping) threads whose address space was
    /// revoked.
    fn pick_runnable(&mut self) -> Option<KPtr<Thread>> {
        loop {
            let t = self.pick()?;
            // SAFETY: see impl.
            if unsafe { t.get() }.space().is_some() {
                return Some(t);
            }
            self.suspend(t);
        }
    }

    /// Takes `t` off the CPU after it blocked or ended.
    pub fn leave_cpu(&mut self, t: KPtr<Thread>) {
        if self.current == Some(t) {
            self.current = None;
        }
    }

    pub fn yield_current(&mut self, t: KPtr<Thread>) {
        // SAFETY: see impl.
        unsafe { t.get() }.timeslice = TIMESLICE_TICKS;
        self.leave_cpu(t);
        self.enqueue(t, false);
    }

    /// Arms a timeout of `ns` nanoseconds (0: none) for a thread about to block.
    pub fn set_timeout(&mut self, t: KPtr<Thread>, ns: u64) {
        if ns == 0 {
            return;
        }
        let deadline = timer::now().saturating_add(timer::ns_to_ticks(ns).max(1));
        // SAFETY: see impl.
        unsafe { t.get() }.deadline = Some(deadline);
        self.timers.insert_by(t, timer_link, |other| other.deadline.is_some_and(|d| d > deadline));
    }

    pub fn cancel_timeout(&mut self, t: KPtr<Thread>) {
        // SAFETY: see impl.
        if unsafe { t.get() }.deadline.take().is_some() {
            self.timers.remove(t, timer_link);
        }
    }

    /// Wakes `t` with `Timeout`, taking it out of whatever it waits on.
    fn time_out(&mut self, t: KPtr<Thread>) {
        self.detach(t);
        // SAFETY: see impl.
        unsafe { t.get() }.set_status(aos_abi::Error::Timeout);
        self.make_ready(t);
    }

    /// Removes a blocked thread from the queue it waits in.
    fn detach(&mut self, t: KPtr<Thread>) {
        // SAFETY: see impl.
        let blocked = core::mem::replace(&mut unsafe { t.get() }.blocked_on, Blocked::Nothing);
        match blocked {
            // SAFETY: see impl.
            Blocked::Endpoint(ep) => unsafe { ep.get() }.remove(t),
            // SAFETY: see impl.
            Blocked::Notification(n) => unsafe { n.get() }.remove(t),
            Blocked::Nothing => {}
        }
    }

    /// Ends the current thread.
    pub fn exit(&mut self, t: KPtr<Thread>, exit: Exit) {
        self.cancel_timeout(t);
        // SAFETY: see impl.
        let th = unsafe { t.get() };
        th.state = ThreadState::Inactive;
        th.exit = Some(exit);
        self.leave_cpu(t);
    }

    /// Stops `t` wherever it is; it never runs again.
    pub fn suspend(&mut self, t: KPtr<Thread>) {
        // SAFETY: see impl.
        let state = unsafe { t.get() }.state;
        match state {
            ThreadState::Ready => self.dequeue(t),
            ThreadState::Running => self.leave_cpu(t),
            ThreadState::BlockedSend | ThreadState::BlockedRecv | ThreadState::BlockedWait => self.detach(t),
            ThreadState::BlockedReply | ThreadState::Inactive => {}
        }
        self.cancel_timeout(t);
        // SAFETY: see impl.
        unsafe { t.get() }.state = ThreadState::Inactive;
    }

    fn tick(&mut self, ticks: u64) {
        self.stats.ticks += ticks;
        let now = timer::now();
        while let Some(t) = self.timers.front() {
            // SAFETY: see impl.
            if unsafe { t.get() }.deadline.is_some_and(|d| d > now) {
                break;
            }
            self.cancel_timeout(t);
            self.time_out(t);
        }
        if let Some(cur) = self.current {
            // SAFETY: see impl.
            let th = unsafe { cur.get() };
            th.timeslice = th.timeslice.saturating_sub(ticks as u32);
            if th.timeslice == 0 {
                th.timeslice = TIMESLICE_TICKS;
                let others = !self.ready[th.priority as usize].is_empty();
                self.current = None;
                self.enqueue(cur, false);
                if others {
                    self.stats.preemptions += 1;
                }
            }
        }
    }

    fn switch_to(&mut self, t: KPtr<Thread>) {
        if self.fp_owner != Some(t) {
            if let Some(owner) = self.fp_owner {
                // SAFETY: see impl; `owner != t`.
                user::fp_save(&mut unsafe { owner.get() }.fp);
            }
            // SAFETY: see impl.
            user::fp_restore(&unsafe { t.get() }.fp);
            self.fp_owner = Some(t);
        }
        if self.last_run != Some(t) {
            // SAFETY: see impl; `pick_runnable` checked that the space exists.
            unsafe { t.get().space().expect("checked").get() }.activate();
            self.last_run = Some(t);
            self.stats.switches += 1;
        }
    }

    fn fault(&mut self, t: KPtr<Thread>, vector: u64, esr: u64, far: u64) {
        // SAFETY: see impl.
        let (id, elr) = {
            let th = unsafe { t.get() };
            (th.id, th.ctx.elr)
        };
        kprintln!("thread {id}: fault (vector {vector}) ESR={esr:#x} FAR={far:#x} ELR={elr:#x}");
        self.exit(t, Exit::Fault { vector, esr, far, elr });
    }

    fn handle_exit(&mut self, t: KPtr<Thread>, vector: u64) {
        let esr = cpu::esr_el1();
        let far = cpu::far_el1();
        match vector {
            EL0_SYNC if exception_class(esr) == ec::SVC64 => syscall::handle(self, t),
            EL0_IRQ => irq::handle(),
            _ => self.fault(t, vector, esr, far),
        }
    }

    /// Runs threads until `done` holds (checked between traps) or the counter reaches
    /// `give_up_at`; returns whether `done` was reached. Idles when nothing is runnable.
    pub fn run_until(&mut self, mut done: impl FnMut(&mut Kernel) -> bool, give_up_at: u64) -> bool {
        loop {
            let ticks = irq::take_ticks();
            if ticks > 0 {
                self.tick(ticks);
            }
            if done(self) {
                return true;
            }
            if timer::now() >= give_up_at {
                return false;
            }
            let Some(t) = self.pick_runnable() else {
                user::wait_for_interrupt();
                continue;
            };
            self.switch_to(t);
            // SAFETY: `t` is the current thread with a valid EL0 context in its own address
            // space (just activated); nothing else references the context while it runs.
            let vector = unsafe { user::enter(&raw mut t.get().ctx) };
            self.handle_exit(t, vector);
        }
    }
}
