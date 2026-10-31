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
    /// An Untyped has no room left; or a CNode or address space is full.
    NoMemory = 7,
    /// The destination slot is not empty.
    SlotInUse = 8,
    /// The address is already mapped, or the frame already is.
    AlreadyMapped = 9,
    UnknownMethod = 10,
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
            7 => Error::NoMemory,
            8 => Error::SlotInUse,
            9 => Error::AlreadyMapped,
            10 => Error::UnknownMethod,
            _ => return None,
        })
    }
}

/// Message words passed in registers (x2–x5).
pub const MSG_REGS: usize = 4;
/// Longest message: words beyond `MSG_REGS` travel in the IPC buffer.
pub const MAX_MSG_WORDS: usize = 64;

/// Bits 63..12: label (chosen by the sender, delivered unchanged; for kernel objects, the
/// method). Bits 10..8: number of capabilities transferred. Bits 7..0: length in words
/// (≤ `MAX_MSG_WORDS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgInfo(pub u64);

/// Capabilities one message can carry.
pub const MAX_MSG_CAPS: usize = 3;

impl MsgInfo {
    pub const fn new(label: u64, len: usize) -> MsgInfo {
        MsgInfo((label << 12) | (len as u64 & 0xff))
    }

    pub const fn with_caps(self, caps: usize) -> MsgInfo {
        MsgInfo((self.0 & !(0x7 << 8)) | ((caps as u64 & 0x7) << 8))
    }

    pub const fn label(self) -> u64 {
        self.0 >> 12
    }

    pub const fn len(self) -> usize {
        (self.0 & 0xff) as usize
    }

    pub const fn caps(self) -> usize {
        ((self.0 >> 8) & 0x7) as usize
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
    /// Sending: the slots of the capabilities to transfer (`MsgInfo::caps` of them).
    pub caps: [u64; MAX_MSG_CAPS],
    /// Receiving: the first free slot received capabilities go to (0: accept none). They are
    /// placed in consecutive slots; `MsgInfo::caps` of the received message says how many.
    pub recv_slot: u64,
    pub reserved: [u64; 60],
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
    /// Root task only: the `BootInfo` page and the boot modules (read-only).
    pub const BOOT_INFO: u64 = 0x0000_7fff_fe00_0000;
    pub const MODULES: u64 = 0x0000_7000_0000_0000;
}

/// Kernel object types, for `untyped::RETYPE`.
pub mod object {
    pub const ENDPOINT: u64 = 1;
    pub const NOTIFICATION: u64 = 2;
    /// A thread (TCB).
    pub const THREAD: u64 = 3;
    /// A capability space of `CNODE_SLOTS` slots.
    pub const CNODE: u64 = 4;
    /// An address space with a pool for its translation tables.
    pub const ADDRESS_SPACE: u64 = 5;
    /// A 4 KiB page of memory, zeroed.
    pub const FRAME: u64 = 6;

    /// Bytes each object takes out of an Untyped (also its alignment).
    pub const fn size(kind: u64) -> Option<u64> {
        match kind {
            ENDPOINT | NOTIFICATION => Some(64),
            THREAD | FRAME => Some(4096),
            CNODE => Some(32 * 1024),
            ADDRESS_SPACE => Some(64 * 1024),
            _ => None,
        }
    }
}

/// Slots in every CNode.
pub const CNODE_SLOTS: u64 = 256;

/// Methods of kernel objects: `CALL` on the object's capability with the method as label.
/// Capability arguments are slots in the caller's CNode.
pub mod method {
    /// Untyped: `(kind, dest_slot, count)` → carve `count` objects into the caller's slots
    /// `dest_slot..`.
    pub const RETYPE: u64 = 1;
    /// CNode: `(src_slot, dest_index, rights)` → copy a capability of the caller into this
    /// CNode, with rights reduced to `rights`.
    pub const COPY: u64 = 2;
    /// CNode: `(src_slot, dest_index, rights, badge)` → as COPY, and badge an unbadged
    /// endpoint or notification capability.
    pub const MINT: u64 = 3;
    /// CNode: `(src_slot, dest_index)` → move a capability of the caller into this CNode.
    pub const MOVE: u64 = 4;
    /// CNode: `(index)` → delete the capability.
    pub const DELETE: u64 = 5;
    /// CNode: `(index)` → delete every capability derived from it.
    pub const REVOKE: u64 = 6;
    /// Thread: `(cnode_slot, space_slot, ipc_buffer_frame_slot or 0, priority)`.
    pub const CONFIGURE: u64 = 7;
    /// Thread: `(pc, sp, arg0, arg1)`.
    pub const WRITE_REGISTERS: u64 = 8;
    pub const RESUME: u64 = 9;
    pub const SUSPEND: u64 = 10;
    /// AddressSpace: `(frame_slot, va, rights)` with `rights` bits `WRITE`/`EXECUTE`.
    pub const MAP: u64 = 11;
    /// Frame: unmap it.
    pub const UNMAP: u64 = 12;
    /// Debug: print a summary of every capability space (§B10 capability audit).
    pub const DUMP_CAPS: u64 = 13;

    pub const WRITE: u64 = 1;
    pub const EXECUTE: u64 = 2;
}

/// Capability rights (endpoint and notification caps; `COPY`/`MINT` masks).
pub mod rights {
    pub const SEND: u64 = 1;
    pub const RECV: u64 = 2;
    /// Capabilities may be transferred through the endpoint.
    pub const GRANT: u64 = 4;
    pub const ALL: u64 = 7;
}

/// Where the kernel puts the root task's initial capabilities.
pub mod root_slots {
    pub const THREAD: u64 = 1;
    pub const CNODE: u64 = 2;
    pub const ADDRESS_SPACE: u64 = 3;
    /// Present in debug kernels only.
    pub const DEBUG: u64 = 4;
    /// Untyped capabilities start here; `BootInfo` says how many.
    pub const FIRST_UNTYPED: u64 = 16;
}

pub const MAX_UNTYPED: usize = 64;
pub const MAX_MODULES: usize = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UntypedInfo {
    pub base: u64,
    pub size_bits: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModuleInfo {
    pub name: [u8; 16],
    /// Where the image is mapped (read-only) in the root task.
    pub va: u64,
    pub len: u64,
}

/// What the kernel tells the root task, at `layout::BOOT_INFO`.
#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub untyped_count: u64,
    pub untyped: [UntypedInfo; MAX_UNTYPED],
    pub module_count: u64,
    pub modules: [ModuleInfo; MAX_MODULES],
    /// The first slot of the root CNode the kernel left empty.
    pub first_free_slot: u64,
}

pub const BOOT_INFO_MAGIC: u64 = 0x414f_535f_424f_4f54; // "AOS_BOOT"

const _: () = assert!(core::mem::size_of::<BootInfo>() <= 4096);

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

/// More `ktest` modes (B-2).
pub mod ktest_b2 {
    /// Asks the memory server (endpoint in `ktest::SLOT_ENDPOINT`) for a frame, maps it
    /// with the address space capability in `SLOT_SPACE`, and checks it.
    pub const MEM_CLIENT: u64 = 11;
    pub const SLOT_SPACE: u64 = 4;
    /// Where the client receives the frame.
    pub const SLOT_RECEIVED: u64 = 10;
}
