//! Protocols between user-space servers.

/// The memory server (§B4: "为其他进程分配内存").
pub mod memory {
    /// `(count ≤ 3)` → `(count given)`, with that many frame capabilities transferred.
    pub const ALLOC_FRAMES: u64 = 1;
    /// Reply label for a request the server does not understand.
    pub const UNKNOWN: u64 = 0xfff;
}

/// virtio-blk driver. A read or write carries one frame capability; the transfer is
/// `min(8, frame pages)` sectors starting at `lba`.
pub mod blk {
    pub const READ: u64 = 1;
    pub const WRITE: u64 = 2;
    pub const FLUSH: u64 = 3;
    /// `()` → `(capacity in sectors)`.
    pub const CAPACITY: u64 = 4;
}

/// virtio-console byte pipe used by the host IPC adapter (§B10).
pub mod hostlink {
    /// Client → host. Word 0 is the byte count; the bytes follow in the message.
    pub const TX: u64 = 1;
    /// Host → client. Same layout in the reply.
    pub const RX: u64 = 2;
    /// Bytes of payload in one chunk (message word 0 is the length, not payload).
    pub const CHUNK: usize = 496;
}
