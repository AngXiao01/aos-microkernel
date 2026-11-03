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

/// virtio-net driver. One lent frame carries the ethernet frame (no virtio header).
pub mod net {
    /// Transmit `words[0]` bytes from the lent frame.
    pub const TX: u64 = 1;
    /// Receive one frame into the lent frame. `words[0] = 0` if none is waiting.
    pub const RX: u64 = 2;
    /// `()` → six MAC bytes packed into `words[0]` (low) and `words[1]`.
    pub const MAC: u64 = 3;
}

/// netstack. The outbound endpoint accepts these; the inbound endpoint rejects CONNECT and UDP.
pub mod stack {
    /// `(ipv4, port)` → `(conn)`.
    pub const CONNECT: u64 = 1;
    /// `(conn, len)` and that many bytes in the lent frame.
    pub const SEND: u64 = 2;
    /// `(conn)` → `(len)` and bytes in the lent frame. `len = 0` is timeout / closed.
    pub const RECV: u64 = 3;
    pub const CLOSE: u64 = 4;
    /// `(ipv4, port, len)` query in the frame → `(len)` response in the frame.
    pub const UDP: u64 = 5;
    /// Inbound side tried to originate traffic (BS6).
    pub const DENIED: u64 = 0x0E00;
    /// Badge of the send capability that may originate connections. Only egress holds it.
    pub const BADGE_OUTBOUND: u64 = 0xE6;
    /// Badge of the listen capability. View holds it and cannot connect.
    pub const BADGE_INBOUND: u64 = 0x1B;
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
