//! AOS core data model (SPEC §6): objects, types, deterministic CBOR, hashes and ULIDs.
//!
//! `no_std + alloc`, no I/O: time and randomness are always supplied by the caller.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cbor;
pub mod codec;
pub mod hash;
pub mod object;
pub mod types;
pub mod ulid;
pub mod value;

pub use cbor::{Cbor, CborMap, DecodeError};
pub use codec::{FormatError, FromCbor, ToCbor, from_bytes, to_bytes};
pub use hash::Hash256;
pub use object::{Actor, Name, Object, Origin, Provenance, Sensitivity, Taint, Timestamp};
pub use types::{
    DefinitionError, Evolution, EvolutionError, FieldKind, FieldSpec, Relation, TypeDef, TypeId, TypeName,
    ValidationError, ViewHint, check_evolution,
};
pub use ulid::{Ulid, UlidError, UlidGenerator};
pub use value::{Finite, ObjectRef, Value};
