//! B-1 acceptance tests: user threads, scheduling, address spaces and IPC, driven through
//! `services/ktest-user` (built into the test kernel by build.rs).

use aos_abi::ktest::*;

use crate::arch::exception::{EL0_SYNC, ec, exception_class};
use crate::arch::timer;
use crate::cap::{Cap, Rights};
use crate::ipc::{Endpoint, Notification};
use crate::kobj::KPtr;
use crate::process;
use crate::sched::{KERNEL, Kernel};
use crate::thread::{Exit, Thread, ThreadState};

static IMAGE: &[u8] = include_bytes!(concat!(env!("AOS_KTEST_USER_DIR"), "/ktest-user"));

fn spawn(k: &mut Kernel, mode: u64, arg: u64, priority: u8) -> KPtr<Thread> {
    process::spawn(k, IMAGE, priority, [mode, arg]).expect("spawn ktest-user")
}

fn give(t: KPtr<Thread>, slot: u64, cap: Cap) {
    // SAFETY: test setup; the thread has not run and nothing else references its CNode.
    unsafe { t.get().cspace.get() }.set(slot as usize, cap);
}

fn endpoint() -> KPtr<Endpoint> {
    KPtr::new(Endpoint::new()).expect("endpoint")
}

fn exit_of(t: KPtr<Thread>) -> Option<Exit> {
    // SAFETY: the run loop has returned; nothing else references the thread.
    unsafe { t.get() }.exit
}

/// Runs until every thread in `threads` has ended or `seconds` pass; then suspends them.
fn run(k: &mut Kernel, threads: &[KPtr<Thread>], seconds: u64) -> bool {
    let give_up = timer::now() + seconds * timer::frequency();
    let finished = k.run_until(
        |_| {
            // SAFETY: called between traps; no thread is running.
            threads.iter().all(|t| unsafe { t.get() }.state == ThreadState::Inactive)
        },
        give_up,
    );
    for t in threads {
        k.suspend(*t);
    }
    finished
}

ktest! {
    fn ipc_ping_pong() {
        let mut k = KERNEL.lock();
        let ep = endpoint();
        let server = spawn(&mut k, PING_SERVER, 0, 10);
        let client = spawn(&mut k, PING_CLIENT, 2000, 10);
        give(server, SLOT_ENDPOINT, Cap::Endpoint { ep, badge: 0, rights: Rights::RECV });
        give(client, SLOT_ENDPOINT, Cap::Endpoint { ep, badge: 7, rights: Rights::SEND });
        let syscalls = k.stats.syscalls;
        kassert!(run(&mut k, &[server, client], 30), "ping-pong did not finish");
        kassert_eq!(exit_of(client), Some(Exit::Code(0)));
        kassert_eq!(exit_of(server), Some(Exit::Code(0)));
        kassert!(k.stats.syscalls - syscalls >= 4000, "expected ≥ 4000 system calls");
    }

    fn preemption_preserves_every_register() {
        let mut k = KERNEL.lock();
        let threads = [
            spawn(&mut k, REGCHECK, 0x1111_0000, 10),
            spawn(&mut k, REGCHECK, 0x2222_0000, 10),
            spawn(&mut k, REGCHECK, 0x3333_0000, 10),
        ];
        let preemptions = k.stats.preemptions;
        kassert!(run(&mut k, &threads, 120), "register check did not finish");
        for t in threads {
            kassert_eq!(exit_of(t), Some(Exit::Code(0)));
        }
        let preempted = k.stats.preemptions - preemptions;
        kprintln!("    {preempted} timer preemptions");
        kassert!(preempted >= 6, "only {preempted} preemptions: the threads did not interleave");
    }

    fn receive_times_out() {
        let mut k = KERNEL.lock();
        let t = spawn(&mut k, TIMEOUT, 5_000_000, 10);
        give(t, SLOT_ENDPOINT, Cap::Endpoint { ep: endpoint(), badge: 0, rights: Rights::RECV });
        kassert!(run(&mut k, &[t], 10));
        kassert_eq!(exit_of(t), Some(Exit::Code(0)));
    }

    fn faults_stop_only_the_faulting_thread() {
        let mut k = KERNEL.lock();
        let cases = [
            (FAULT_READ_KERNEL, ec::DABT_LOWER),
            (FAULT_WRITE_TEXT, ec::DABT_LOWER),
            (FAULT_EXEC_STACK, ec::IABT_LOWER),
            (FAULT_UNDEFINED, ec::UNKNOWN),
        ];
        for (kind, class) in cases {
            let t = spawn(&mut k, FAULT, kind, 10);
            kassert!(run(&mut k, &[t], 10));
            match exit_of(t) {
                Some(Exit::Fault { vector, esr, .. }) => {
                    kassert_eq!(vector, EL0_SYNC);
                    kassert_eq!(exception_class(esr), class, "fault kind {kind}");
                }
                other => kfail!("fault kind {kind}: thread ended with {other:?}"),
            }
        }
    }

    fn invalid_calls_fail_cleanly() {
        let mut k = KERNEL.lock();
        let t = spawn(&mut k, BAD_CALLS, 0, 10);
        give(t, SLOT_ENDPOINT, Cap::Endpoint { ep: endpoint(), badge: 0, rights: Rights::ALL });
        let ntfn = KPtr::new(Notification::new()).unwrap();
        give(t, SLOT_NOTIFICATION, Cap::Notification { ntfn, badge: 1, rights: Rights::ALL });
        kassert!(run(&mut k, &[t], 10));
        kassert_eq!(exit_of(t), Some(Exit::Code(0)));
    }

    fn notification_bits_accumulate_and_wake_waiters() {
        let mut k = KERNEL.lock();
        // Signallers first (higher priority): the bits accumulate before anyone waits.
        let ntfn = KPtr::new(Notification::new()).unwrap();
        let a = spawn(&mut k, NOTIFY_SIGNAL, 0, 20);
        let b = spawn(&mut k, NOTIFY_SIGNAL, 0, 20);
        let w = spawn(&mut k, NOTIFY_WAIT, 0, 10);
        give(a, SLOT_NOTIFICATION, Cap::Notification { ntfn, badge: 0b001, rights: Rights::SEND });
        give(b, SLOT_NOTIFICATION, Cap::Notification { ntfn, badge: 0b100, rights: Rights::SEND });
        give(w, SLOT_NOTIFICATION, Cap::Notification { ntfn, badge: 0, rights: Rights::RECV });
        kassert!(run(&mut k, &[a, b, w], 10));
        kassert_eq!(exit_of(w), Some(Exit::Code(0b101)));

        // The waiter first (higher priority): it blocks, and the signal wakes it.
        let ntfn = KPtr::new(Notification::new()).unwrap();
        let w = spawn(&mut k, NOTIFY_WAIT, 0, 20);
        let s = spawn(&mut k, NOTIFY_SIGNAL, 0, 10);
        give(w, SLOT_NOTIFICATION, Cap::Notification { ntfn, badge: 0, rights: Rights::RECV });
        give(s, SLOT_NOTIFICATION, Cap::Notification { ntfn, badge: 0b10, rights: Rights::SEND });
        kassert!(run(&mut k, &[w, s], 10));
        kassert_eq!(exit_of(w), Some(Exit::Code(0b10)));
    }

    fn blocked_senders_are_served_in_fifo_order() {
        let mut k = KERNEL.lock();
        let ep = endpoint();
        // Higher-priority senders run first and queue up in spawn order.
        let senders = [spawn(&mut k, FIFO_SENDER, 1, 20), spawn(&mut k, FIFO_SENDER, 2, 20), spawn(&mut k, FIFO_SENDER, 3, 20)];
        let receiver = spawn(&mut k, FIFO_RECEIVER, 3, 10);
        for s in senders {
            give(s, SLOT_ENDPOINT, Cap::Endpoint { ep, badge: 0, rights: Rights::SEND });
        }
        give(receiver, SLOT_ENDPOINT, Cap::Endpoint { ep, badge: 0, rights: Rights::RECV });
        kassert!(run(&mut k, &[senders[0], senders[1], senders[2], receiver], 10));
        kassert_eq!(exit_of(receiver), Some(Exit::Code(0x321)));
    }

    fn rights_are_enforced() {
        let mut k = KERNEL.lock();
        let ep = endpoint();
        // A receive-only capability cannot send: FIFO_SENDER exits with the status.
        let t = spawn(&mut k, FIFO_SENDER, 1, 10);
        give(t, SLOT_ENDPOINT, Cap::Endpoint { ep, badge: 0, rights: Rights::RECV });
        kassert!(run(&mut k, &[t], 10));
        kassert_eq!(exit_of(t), Some(Exit::Code(aos_abi::Error::NoRight as u64)));
    }
}
