//! The AOS host ABI for WASM core modules (SPEC §8.4).
//!
//! An action module imports only functions from module `aos`, exports its `memory`,
//! `aos_alloc(len) -> ptr` and `run(ptr, len) -> i32`. The runtime writes the bound inputs
//! (a CBOR map) into memory obtained from `aos_alloc` and calls `run`; 0 means success,
//! anything else aborts the transaction.
//!
//! Every host function except `aos_log` and `aos_output` has the signature
//! `(in_ptr, in_len, out_ptr, out_cap) -> i32`: CBOR in, CBOR out. A non-negative result
//! is the output length; if it exceeds `out_cap`, nothing was written and the call may be
//! repeated with a larger buffer. Negative results are the errors below. Using a type,
//! object or channel the declaration or capability does not allow is not an error: it is a
//! violation, which ends the action.

pub const MODULE: &str = "aos";

/// `{"id": ulid}` → the object (`aos_types::Object` encoding).
pub const READ: &str = "aos_read";
/// `{"id", "expected_version", "fields": {name: value | null}}` → `{"version"}`. `null`
/// removes a field.
pub const WRITE: &str = "aos_write";
/// `{"id", "expected_version"}` → `{"version"}` (tombstone).
pub const DELETE: &str = "aos_delete";
/// `{"type": "ns/Name@major", "fields": {...}}` → `{"id"}`.
pub const CREATE: &str = "aos_create";
/// `{"from": "ns/Name@major", "where"?: {field: value}, "limit"?: n}` → `[id, ...]`.
pub const QUERY: &str = "aos_query";
/// Raw bytes → the 32-byte SHA-256 of the stored blob.
pub const BLOB_WRITE: &str = "aos_blob_write";
/// `{"hash", "offset", "len"}` → a CBOR byte string.
pub const BLOB_READ: &str = "aos_blob_read";
/// `{"channel", "target", "summary", "blobs": [hash]}` → `{"id"}` of the new
/// `sys/EgressIntent`.
pub const INTENT_CREATE: &str = "aos_intent_create";
/// As `INTENT_CREATE` on a `compute:*` channel: submitting a job is an egress (SPEC §8.5).
pub const JOB_SUBMIT: &str = "aos_job_submit";
/// `(level, ptr, len) -> 0`.
pub const LOG: &str = "aos_log";
/// `(ptr, len) -> 0`: the action's outputs, a CBOR map checked against the declaration.
pub const OUTPUT: &str = "aos_output";

pub const ERR_NOT_FOUND: i32 = -1;
pub const ERR_BAD_ARGUMENT: i32 = -2;
/// The expected version is not the current one.
pub const ERR_CONFLICT: i32 = -3;
