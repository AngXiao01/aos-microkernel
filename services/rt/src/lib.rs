//! AOS user-space runtime: program entry, system calls, IPC, debug output.
//!
//! A program provides `fn main(arg0: u64, arg1: u64) -> u64` through [`entry!`]; the
//! kernel starts it with the two arguments in x0/x1, the stack pointer at
//! `layout::STACK_TOP` and the IPC buffer mapped at `layout::IPC_BUFFER`. Returning ends
//! the thread with the returned exit code.

#![no_std]

pub use aos_abi as abi;
use aos_abi::{Error, IpcBuffer, MSG_REGS, MsgInfo, layout, sys};

pub mod cap;
pub mod debug;
pub mod pipe;
pub mod proto;

core::arch::global_asm!(
    ".pushsection .text._start, \"ax\"",
    ".global _start",
    "_start:",
    "    bl aos_rt_start",
    "1:  b 1b",
    ".popsection",
);

unsafe extern "Rust" {
    fn __aos_main(arg0: u64, arg1: u64) -> u64;
}

#[unsafe(no_mangle)]
extern "C" fn aos_rt_start(arg0: u64, arg1: u64) -> ! {
    // SAFETY: `entry!` defines `__aos_main` with this signature.
    let code = unsafe { __aos_main(arg0, arg1) };
    exit(code)
}

/// Declares the program's main function: `entry!(main)` with `fn main(u64, u64) -> u64`.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        fn __aos_main(arg0: u64, arg1: u64) -> u64 {
            let f: fn(u64, u64) -> u64 = $main;
            f(arg0, arg1)
        }
    };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("panic: {info}");
    exit(0xdead)
}

/// Registers after a system call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub status: u64,
    pub info: MsgInfo,
    pub words: [u64; MSG_REGS],
    pub badge: u64,
}

impl Reply {
    pub fn error(&self) -> Option<Error> {
        Error::from_u64(self.status)
    }

    pub fn is_ok(&self) -> bool {
        self.status == Error::Ok as u64
    }
}

/// A raw system call: `regs` are x0–x6 in and out.
#[inline(always)]
pub fn syscall(number: u64, regs: [u64; 7]) -> Reply {
    let [mut x0, mut x1, mut x2, mut x3, mut x4, mut x5, mut x6] = regs;
    // SAFETY: the kernel only reads and writes x0–x7 and the IPC buffer.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inout("x0") x0, inout("x1") x1, inout("x2") x2, inout("x3") x3,
            inout("x4") x4, inout("x5") x5, inout("x6") x6, in("x7") number,
            options(nostack),
        );
    }
    Reply { status: x0, info: MsgInfo(x1), words: [x2, x3, x4, x5], badge: x6 }
}

fn message(slot: u64, info: MsgInfo, words: [u64; MSG_REGS], timeout_ns: u64) -> [u64; 7] {
    [slot, info.0, words[0], words[1], words[2], words[3], timeout_ns]
}

pub fn call(slot: u64, info: MsgInfo, words: [u64; MSG_REGS], timeout_ns: u64) -> Reply {
    syscall(sys::CALL, message(slot, info, words, timeout_ns))
}

pub fn send(slot: u64, info: MsgInfo, words: [u64; MSG_REGS]) -> Reply {
    syscall(sys::SEND, message(slot, info, words, 0))
}

pub fn recv(slot: u64, timeout_ns: u64) -> Reply {
    syscall(sys::RECV, [slot, 0, 0, 0, 0, 0, timeout_ns])
}

pub fn reply(info: MsgInfo, words: [u64; MSG_REGS]) -> Reply {
    syscall(sys::REPLY, message(0, info, words, 0))
}

pub fn reply_recv(slot: u64, info: MsgInfo, words: [u64; MSG_REGS]) -> Reply {
    syscall(sys::REPLY_RECV, message(slot, info, words, 0))
}

pub fn yield_now() {
    syscall(sys::YIELD, [0; 7]);
}

pub fn signal(slot: u64) -> Reply {
    syscall(sys::SIGNAL, [slot, 0, 0, 0, 0, 0, 0])
}

/// Returns the notification bits in `words[0]`.
pub fn wait(slot: u64, timeout_ns: u64) -> Reply {
    syscall(sys::WAIT, [slot, 0, 0, 0, 0, 0, timeout_ns])
}

pub fn exit(code: u64) -> ! {
    syscall(sys::THREAD_EXIT, [code, 0, 0, 0, 0, 0, 0]);
    unreachable!("THREAD_EXIT returned")
}

/// This thread's IPC buffer.
pub fn ipc_buffer() -> &'static mut IpcBuffer {
    // SAFETY: the kernel maps a page-sized, page-aligned IPC buffer at this address for
    // every thread it starts, and only this thread uses it.
    unsafe { &mut *(layout::IPC_BUFFER as *mut IpcBuffer) }
}

/// The virtual counter (CNTVCT_EL0, readable from EL0) and its frequency.
pub fn counter() -> u64 {
    let v: u64;
    // SAFETY: the kernel enables EL0 access to the virtual counter.
    unsafe { core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

pub fn counter_frequency() -> u64 {
    let v: u64;
    // SAFETY: CNTFRQ_EL0 is readable from EL0.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}
