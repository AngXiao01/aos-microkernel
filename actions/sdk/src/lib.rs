//! Guest side of the AOS host ABI (SPEC §8.4; see `aos_action::abi`).
//!
//! An action implements `fn(inputs: CborMap) -> Result<(), i32>` and names it with
//! [`action!`]; the SDK provides the exports the runtime calls (`aos_alloc`, `run`), a bump
//! allocator, and typed wrappers around the host functions.

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

pub use aos_types;
use aos_types::cbor::{self, Cbor, CborMap};

#[link(wasm_import_module = "aos")]
unsafe extern "C" {
    fn aos_read(ip: *const u8, il: usize, op: *mut u8, oc: usize) -> i32;
    fn aos_write(ip: *const u8, il: usize, op: *mut u8, oc: usize) -> i32;
    fn aos_delete(ip: *const u8, il: usize, op: *mut u8, oc: usize) -> i32;
    fn aos_create(ip: *const u8, il: usize, op: *mut u8, oc: usize) -> i32;
    fn aos_query(ip: *const u8, il: usize, op: *mut u8, oc: usize) -> i32;
    fn aos_blob_write(ip: *const u8, il: usize, op: *mut u8, oc: usize) -> i32;
    fn aos_blob_read(ip: *const u8, il: usize, op: *mut u8, oc: usize) -> i32;
    fn aos_intent_create(ip: *const u8, il: usize, op: *mut u8, oc: usize) -> i32;
    fn aos_job_submit(ip: *const u8, il: usize, op: *mut u8, oc: usize) -> i32;
    fn aos_log(level: i32, ptr: *const u8, len: usize) -> i32;
    fn aos_output(ptr: *const u8, len: usize) -> i32;
}

/// A host call that failed with one of the ABI's negative codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostError(pub i32);

type Raw = unsafe extern "C" fn(*const u8, usize, *mut u8, usize) -> i32;

fn call(f: Raw, input: &[u8]) -> Result<Vec<u8>, HostError> {
    let mut out = vec![0u8; 256];
    loop {
        // SAFETY: the host reads `input` and writes at most `out.len()` bytes into `out`.
        let n = unsafe { f(input.as_ptr(), input.len(), out.as_mut_ptr(), out.len()) };
        if n < 0 {
            return Err(HostError(n));
        }
        let n = n as usize;
        if n <= out.len() {
            out.truncate(n);
            return Ok(out);
        }
        out = vec![0u8; n]; // only calls without side effects can come back larger than 64 bytes
    }
}

fn call_map(f: Raw, input: CborMap) -> Result<Cbor, HostError> {
    let out = call(f, &cbor::encode(&Cbor::Map(input)))?;
    cbor::decode(&out).map_err(|_| HostError(-100))
}

pub fn map(entries: impl IntoIterator<Item = (&'static str, Cbor)>) -> CborMap {
    entries.into_iter().map(|(k, v)| (Cbor::text(k), v)).collect()
}

macro_rules! host_fns {
    ($($(#[$doc:meta])* $name:ident => $raw:ident;)*) => {
        $(
            $(#[$doc])*
            pub fn $name(input: CborMap) -> Result<Cbor, HostError> {
                call_map($raw, input)
            }
        )*
    };
}

host_fns! {
    /// `{"id"}` → object.
    read => aos_read;
    /// `{"id", "expected_version", "fields"}` → `{"version"}`.
    write => aos_write;
    /// `{"id", "expected_version"}` → `{"version"}`.
    delete => aos_delete;
    /// `{"type", "fields"}` → `{"id"}`.
    create => aos_create;
    /// `{"from", "where"?, "limit"?}` → `[id]`.
    query => aos_query;
    /// `{"hash", "offset", "len"}` → bytes.
    blob_read_raw => aos_blob_read;
    /// `{"channel", "target", "summary", "blobs"?}` → `{"id"}`.
    intent_create => aos_intent_create;
    /// As `intent_create`, on a `compute:*` channel.
    job_submit => aos_job_submit;
}

pub fn blob_write(bytes: &[u8]) -> Result<[u8; 32], HostError> {
    call(aos_blob_write, bytes)?.try_into().map_err(|_| HostError(-100))
}

pub fn blob_read(hash: [u8; 32], offset: u64, len: u64) -> Result<Vec<u8>, HostError> {
    let out = blob_read_raw(map([
        ("hash", Cbor::Bytes(hash.to_vec())),
        ("offset", Cbor::Unsigned(offset)),
        ("len", Cbor::Unsigned(len)),
    ]))?;
    match out {
        Cbor::Bytes(b) => Ok(b),
        _ => Err(HostError(-100)),
    }
}

pub fn log(level: u32, message: &str) {
    // SAFETY: the host only reads the message.
    unsafe { aos_log(level as i32, message.as_ptr(), message.len()) };
}

pub fn output(outputs: CborMap) {
    let bytes = cbor::encode(&Cbor::Map(outputs));
    // SAFETY: the host only reads the bytes.
    unsafe { aos_output(bytes.as_ptr(), bytes.len()) };
}

/// Declares the action's entry point.
#[macro_export]
macro_rules! action {
    ($f:path) => {
        /// # Safety
        /// Called by the runtime with `len` bytes of CBOR at `ptr`, obtained from `aos_alloc`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn run(ptr: *const u8, len: usize) -> i32 {
            // SAFETY: the runtime wrote `len` bytes of CBOR at `ptr`, obtained from aos_alloc.
            let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
            let Some(inputs) = $crate::aos_types::cbor::decode(bytes).ok().and_then(|c| match c {
                $crate::aos_types::cbor::Cbor::Map(m) => Some(m),
                _ => None,
            }) else {
                return -1;
            };
            let f: fn($crate::aos_types::cbor::CborMap) -> Result<(), i32> = $f;
            match f(inputs) {
                Ok(()) => 0,
                Err(code) => code,
            }
        }
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn aos_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    core::mem::forget(v);
    p
}

/// Never frees: an action is a short-lived instance.
struct Bump {
    next: UnsafeCell<usize>,
}

// SAFETY: WASM actions are single-threaded.
unsafe impl Sync for Bump {}

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        const PAGE: usize = 65536;
        // SAFETY: single-threaded; `next` is only touched here.
        let next = unsafe { &mut *self.next.get() };
        if *next == 0 {
            *next = core::arch::wasm32::memory_size(0) * PAGE;
        }
        let start = (*next + layout.align() - 1) & !(layout.align() - 1);
        let end = start + layout.size();
        let have = core::arch::wasm32::memory_size(0) * PAGE;
        if end > have && core::arch::wasm32::memory_grow(0, (end - have).div_ceil(PAGE)) == usize::MAX {
            return core::ptr::null_mut();
        }
        *next = end;
        start as *mut u8
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static ALLOCATOR: Bump = Bump { next: UnsafeCell::new(0) };

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
