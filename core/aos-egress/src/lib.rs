//! The egress gate (SPEC §11): the only place external effects happen.
//!
//! Invariants enforced here (§11.4):
//! 2. Before executing, the payload is hashed again and must match the intent; for a
//!    confirmed intent it must also match the item the user approved ("审的是 A，发出去的是 B").
//! 3. Approvals are single-use and expire (checked by `aos_confirm::ConfirmService`); an
//!    approval only covers the items it lists.
//! 4. Every execution, success or failure, yields a receipt.
//!
//! Without an allow verdict or a verified approval, nothing executes.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{collections::BTreeSet, string::String, vec::Vec};

use aos_confirm::{Decision as Answer, Verified};
use aos_policy::{Decision, Verdict};
use aos_types::cbor::{self, Cbor};
use aos_types::{Hash256, Ulid};

/// The payload of an intent, as the gate hashes it: the deterministic encoding of the list
/// of its blob hashes. Blobs are content-addressed, so this binds the full contents.
pub fn payload_bytes(blobs: &[Hash256]) -> Vec<u8> {
    cbor::encode(&Cbor::Array(blobs.iter().map(|h| Cbor::Bytes(h.0.to_vec())).collect()))
}

pub fn payload_hash(blobs: &[Hash256]) -> Hash256 {
    Hash256::digest(&payload_bytes(blobs))
}

/// An intent as the gate sees it (fields of the `sys/EgressIntent` object).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub id: Ulid,
    pub channel: String,
    pub target: String,
    pub payload_hash: Hash256,
}

/// How an execution was authorized.
pub enum Authorization<'a> {
    /// A standing policy allowed it.
    Policy(Verdict),
    /// The user approved it on the confirmer.
    Approval(&'a Verified),
}

/// The outside world, reached only from here (in AOS, through the netstack's outbound
/// endpoint, which only the egress gateway holds).
pub trait Transport {
    fn send(&mut self, channel: &str, target: &str, payload: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateError {
    /// Neither an allow verdict nor an approval for this intent.
    NotAuthorized,
    Denied,
    /// The payload does not hash to what the intent (or the approval) names.
    PayloadMismatch,
    /// The approval does not list this channel and target.
    NotApproved,
    AlreadyExecuted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub intent: Ulid,
    pub payload_hash: Hash256,
    pub outcome: Result<Vec<u8>, String>,
}

pub struct Gate<T> {
    transport: T,
    executed: BTreeSet<Ulid>,
}

impl<T: Transport> Gate<T> {
    pub fn new(transport: T) -> Gate<T> {
        Gate { transport, executed: BTreeSet::new() }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn execute(&mut self, intent: &Intent, payload: &[u8], auth: Authorization<'_>) -> Result<Receipt, GateError> {
        if self.executed.contains(&intent.id) {
            return Err(GateError::AlreadyExecuted);
        }
        let hash = Hash256::digest(payload);
        if hash != intent.payload_hash {
            return Err(GateError::PayloadMismatch);
        }
        match auth {
            Authorization::Policy(v) => match v.decision {
                Decision::Allow => {}
                Decision::Deny => return Err(GateError::Denied),
                Decision::Confirm => return Err(GateError::NotAuthorized),
            },
            Authorization::Approval(verified) => {
                if verified.decision != Answer::Approve {
                    return Err(GateError::Denied);
                }
                let item = verified
                    .request
                    .items
                    .iter()
                    .find(|i| i.channel == intent.channel && i.target == intent.target)
                    .ok_or(GateError::NotApproved)?;
                if item.payload_hash != hash {
                    return Err(GateError::PayloadMismatch);
                }
            }
        }
        self.executed.insert(intent.id);
        let outcome = self.transport.send(&intent.channel, &intent.target, payload);
        Ok(Receipt { intent: intent.id, payload_hash: hash, outcome })
    }
}
