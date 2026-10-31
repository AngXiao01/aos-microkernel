//! The scheduler and the kernel's run loop (§B3.1): fixed priorities 0–255, round robin
//! within a priority, preemption by the timer tick and by higher-priority wakeups.
//!
//! The run loop is the only place kernel state changes: it picks a thread, runs it until
//! it traps (`arch::user::enter`), and handles the trap. Interrupt handlers only record
//! events (`irq`), which the loop then processes, so one `&mut Kernel` suffices.

use crate::arch::exception::{EL0_IRQ, EL0_SYNC, ec, exception_class};
use crate::arch::{cpu, timer, user};
use crate::irq;
use crate::kobj::KPtr;
use crate::sync::SpinLock;
use crate::syscall;
use crate::thread::{Blocked, Exit, Queue, TIMESLICE_TICKS, Thread, ThreadState, queue_link, timer_link};
use crate::vspace::AsidAllocator;

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
    pub asids: AsidAllocator,
    pub stats: Stats,
    next_id: u32,
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
            asids: AsidAllocator::new(),
            stats: Stats { switches: 0, preemptions: 0, syscalls: 0, ticks: 0 },
            next_id: 1,
        }
    }

    pub fn next_thread_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id - 1
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
            // SAFETY: see impl.
            unsafe { t.get().vspace.get() }.activate();
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
            let Some(t) = self.pick() else {
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
