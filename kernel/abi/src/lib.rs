//! The AOS kernel/user ABI, shared by the kernel and user-space runtime.
//!
//! System calls are `svc #0` with the call number in x7. Arguments:
//! - x0: capability slot (CPtr) the call operates on;
//! - x1: [`MsgInfo`] (label and message length);
//! - x2–x5: message words 0–3; words 4.. are in the IPC buffer;
//! - x6: timeout in nanoseconds for blocking calls (0 = wait forever).
//!
//! Every call returns x0 = status ([`Error`] code, 0 = success), x1 = [`MsgInfo`],
//! x2–x5 = message words 0–3, x6 = badge of the sender (receive operations).

#![no_std]

/// System call numbers (x7).
pub mod sys {
    /// Send to an endpoint and wait for the reply.
    pub const CALL: u64 = 0;
    /// Send to an endpoint, blocking until a receiver takes the message.
    pub const SEND: u64 = 1;
    /// Receive from an endpoint.
    pub const RECV: u64 = 2;
    /// Reply to the thread whose call was received last.
    pub const REPLY: u64 = 3;
    /// `REPLY`, then `RECV` on x0.
    pub const REPLY_RECV: u64 = 4;
    pub const YIELD: u64 = 5;
    /// Set the notification bits named by the capability's badge.
    pub const SIGNAL: u64 = 6;
    /// Wait until a notification has bits set; returns and clears them (x2).
    pub const WAIT: u64 = 7;
    /// End the calling thread; x0 is its exit code.
    pub const THREAD_EXIT: u64 = 8;
    /// Print `x1` bytes from the IPC buffer's debug area. Debug kernels only.
    pub const DEBUG_PUT: u64 = 0x100;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Error {
    Ok = 0,
    /// The slot is empty, out of range, or holds the wrong kind of capability.
    InvalidCap = 1,
    /// The capability lacks the right the operation needs.
    NoRight = 2,
    InvalidArgument = 3,
    /// `REPLY` without a caller waiting for this thread.
    NoReply = 4,
    Timeout = 5,
    UnknownSyscall = 6,
}

impl Error {
    pub fn from_u64(v: u64) -> Option<Error> {
        Some(match v {
            0 => Error::Ok,
            1 => Error::InvalidCap,
            2 => Error::NoRight,
            3 => Error::InvalidArgument,
            4 => Error::NoReply,
            5 => Error::Timeout,
            6 => Error::UnknownSyscall,
            _ => return None,
        })
    }
}

/// Message words passed in registers (x2–x5).
pub const MSG_REGS: usize = 4;
/// Longest message: words beyond `MSG_REGS` travel in the IPC buffer.
pub const MAX_MSG_WORDS: usize = 64;

/// Bits 63..12: label (chosen by the sender, delivered unchanged). Bits 11..0: length in
/// words (≤ `MAX_MSG_WORDS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgInfo(pub u64);

impl MsgInfo {
    pub const fn new(label: u64, len: usize) -> MsgInfo {
        MsgInfo((label << 12) | (len as u64 & 0xfff))
    }

    pub const fn label(self) -> u64 {
        self.0 >> 12
    }

    pub const fn len(self) -> usize {
        (self.0 & 0xfff) as usize
    }

    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// The per-thread IPC buffer, one page mapped at [`layout::IPC_BUFFER`].
#[repr(C)]
pub struct IpcBuffer {
    /// Message words; `msg[..MSG_REGS]` are unused because those travel in registers.
    pub msg: [u64; MAX_MSG_WORDS],
    pub reserved: [u64; 64],
    /// Bytes for `DEBUG_PUT`.
    pub debug: [u8; DEBUG_BYTES],
}

pub const DEBUG_BYTES: usize = 2048;

const _: () = assert!(core::mem::size_of::<IpcBuffer>() <= 4096);

/// User address-space layout set up by the kernel's loader.
pub mod layout {
    /// The lowest address a program may be linked at.
    pub const USER_MIN: u64 = 0x0000_0000_0040_0000;
    /// Exclusive upper bound of user addresses (TTBR0, 48-bit).
    pub const USER_END: u64 = 0x0000_8000_0000_0000;
    pub const IPC_BUFFER: u64 = 0x0000_7fff_ffff_0000;
    /// The initial stack ends here (grows down); an unmapped guard page lies below it.
    pub const STACK_TOP: u64 = 0x0000_7fff_fff0_0000;
    pub const STACK_SIZE: u64 = 64 * 1024;
}

/// Protocol between the kernel's B-1 tests and `services/ktest-user`: the program's mode
/// (x0 at start) and the capability slots the kernel test fills in.
pub mod ktest {
    pub const SLOT_ENDPOINT: u64 = 1;
    pub const SLOT_NOTIFICATION: u64 = 2;
    /// Always empty.
    pub const SLOT_EMPTY: u64 = 3;

    /// Replies to every call with each word plus one until a call labelled `LABEL_STOP`.
    pub const PING_SERVER: u64 = 1;
    /// Makes `arg` calls and checks every reply; prints the mean round trip.
    pub const PING_CLIENT: u64 = 2;
    /// Fills general and FP/SIMD registers with a pattern derived from `arg`, spins, checks.
    pub const REGCHECK: u64 = 3;
    /// Receives with a timeout of `arg` ns from an endpoint nobody sends to.
    pub const TIMEOUT: u64 = 4;
    /// Faults deliberately; `arg` picks how (see `FAULT_*`).
    pub const FAULT: u64 = 5;
    /// Checks that invalid capabilities and system calls fail cleanly.
    pub const BAD_CALLS: u64 = 6;
    /// Waits on the notification; exits with the bits received.
    pub const NOTIFY_WAIT: u64 = 7;
    pub const NOTIFY_SIGNAL: u64 = 8;
    /// Sends one message labelled `arg`.
    pub const FIFO_SENDER: u64 = 9;
    /// Receives `arg` messages; exits with their labels, one hex digit each, first lowest.
    pub const FIFO_RECEIVER: u64 = 10;

    pub const LABEL_STOP: u64 = 0xfff;

    pub const FAULT_READ_KERNEL: u64 = 0;
    pub const FAULT_WRITE_TEXT: u64 = 1;
    pub const FAULT_EXEC_STACK: u64 = 2;
    pub const FAULT_UNDEFINED: u64 = 3;
}
