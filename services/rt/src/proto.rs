//! Protocols between user-space servers.

/// The memory server (§B4: "为其他进程分配内存").
pub mod memory {
    /// `(count ≤ 3)` → `(count given)`, with that many frame capabilities transferred.
    pub const ALLOC_FRAMES: u64 = 1;
    /// Reply label for a request the server does not understand.
    pub const UNKNOWN: u64 = 0xfff;
}
