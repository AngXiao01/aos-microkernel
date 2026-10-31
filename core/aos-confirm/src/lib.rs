//! The confirmer protocol (SPEC §12): approval requests, their signatures, and single-use
//! verification.
//!
//! - The OS (Confirm Service) encodes an [`ApprovalRequest`] as deterministic CBOR and signs
//!   it with its own key, so the confirmer knows where the request came from.
//! - The confirmer (the user's iPhone; a [`DevConfirmer`] in tests) shows the structured
//!   request itself and signs `request_bytes || decision` with its Secure Enclave key.
//! - [`ConfirmService::verify`] accepts an approval only for a pending, unexpired request,
//!   with a valid confirmer signature, and only once.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use aos_types::cbor::{self, Cbor};
use aos_types::codec::MapBuilder;
use aos_types::value::{hash_to_cbor, ulid_to_cbor};
use aos_types::{Hash256, Timestamp, Ulid};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Egress,
    TaskCapabilities,
    PolicyChange,
}

/// One effect to approve, as the confirmer shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub channel: String,
    pub target: String,
    pub payload_hash: Hash256,
    pub cost_fen: u64,
    pub external_reversibility: String,
    /// Shown prominently: the channel or recipient came from external content.
    pub tainted: bool,
}

pub const MAX_SUMMARY_LINES: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub request_id: Ulid,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub nonce: [u8; 16],
    pub kind: Kind,
    /// At most `MAX_SUMMARY_LINES` (label, value) lines of plain text.
    pub summary: Vec<(String, String)>,
    pub items: Vec<Item>,
    pub branch: String,
    pub diff_hash: Hash256,
}

impl ApprovalRequest {
    /// The deterministic encoding both signatures cover.
    pub fn encode(&self) -> Vec<u8> {
        let kind = match self.kind {
            Kind::Egress => "egress",
            Kind::TaskCapabilities => "task_capabilities",
            Kind::PolicyChange => "policy_change",
        };
        let summary = self
            .summary
            .iter()
            .map(|(l, v)| {
                MapBuilder::new().put("label", Cbor::Text(l.clone())).put("value", Cbor::Text(v.clone())).build()
            })
            .collect();
        let items = self
            .items
            .iter()
            .map(|i| {
                MapBuilder::new()
                    .put("channel", Cbor::Text(i.channel.clone()))
                    .put("target", Cbor::Text(i.target.clone()))
                    .put("payload_hash", hash_to_cbor(&i.payload_hash))
                    .put("cost", Cbor::Unsigned(i.cost_fen))
                    .put("external_reversibility", Cbor::Text(i.external_reversibility.clone()))
                    .put("tainted", Cbor::Bool(i.tainted))
                    .build()
            })
            .collect();
        cbor::encode(
            &MapBuilder::new()
                .put("request_id", ulid_to_cbor(self.request_id))
                .put("created_at", Cbor::Unsigned(self.created_at.0))
                .put("expires_at", Cbor::Unsigned(self.expires_at.0))
                .put("nonce", Cbor::Bytes(self.nonce.to_vec()))
                .put("kind", Cbor::text(kind))
                .put("summary", Cbor::Array(summary))
                .put("items", Cbor::Array(items))
                .put("branch", Cbor::Text(self.branch.clone()))
                .put("diff_hash", hash_to_cbor(&self.diff_hash))
                .build(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Deny,
}

impl Decision {
    fn byte(self) -> u8 {
        match self {
            Decision::Approve => 1,
            Decision::Deny => 0,
        }
    }
}

/// What the confirmer sends back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub request_id: Ulid,
    pub decision: Decision,
    pub signature: [u8; 64],
}

fn signed(request_bytes: &[u8], decision: Decision) -> Vec<u8> {
    let mut m = request_bytes.to_vec();
    m.push(decision.byte());
    m
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmError {
    BadKey,
    TooManySummaryLines,
    UnknownRequest,
    Expired,
    BadSignature,
    /// The request was already decided: approvals are single-use (SPEC §11.4.3).
    Replayed,
}

/// A request approved (or denied) by the confirmer, verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub request: ApprovalRequest,
    pub decision: Decision,
}

struct Pending {
    request: ApprovalRequest,
    bytes: Vec<u8>,
}

/// The OS side (Confirm Service, TCB).
pub struct ConfirmService {
    os_key: SigningKey,
    confirmer: VerifyingKey,
    pending: BTreeMap<Ulid, Pending>,
    decided: BTreeMap<Ulid, Decision>,
}

impl ConfirmService {
    /// `confirmer` is the public key stored at pairing (SPEC §12.2).
    pub fn new(os_secret: [u8; 32], confirmer: VerifyingKey) -> Result<ConfirmService, ConfirmError> {
        let os_key = SigningKey::from_bytes(&os_secret.into()).map_err(|_| ConfirmError::BadKey)?;
        Ok(ConfirmService { os_key, confirmer, pending: BTreeMap::new(), decided: BTreeMap::new() })
    }

    pub fn os_key(&self) -> VerifyingKey {
        *self.os_key.verifying_key()
    }

    /// Registers the request; returns its bytes and the OS signature to send to the confirmer.
    pub fn issue(&mut self, request: ApprovalRequest) -> Result<(Vec<u8>, [u8; 64]), ConfirmError> {
        if request.summary.len() > MAX_SUMMARY_LINES {
            return Err(ConfirmError::TooManySummaryLines);
        }
        let bytes = request.encode();
        let sig: Signature = self.os_key.sign(&bytes);
        self.pending.insert(request.request_id, Pending { request, bytes: bytes.clone() });
        Ok((bytes, sig.to_bytes().into()))
    }

    /// Accepts the confirmer's answer once, before the request expires.
    pub fn verify(&mut self, approval: &Approval, now: Timestamp) -> Result<Verified, ConfirmError> {
        if self.decided.contains_key(&approval.request_id) {
            return Err(ConfirmError::Replayed);
        }
        let p = self.pending.get(&approval.request_id).ok_or(ConfirmError::UnknownRequest)?;
        if now >= p.request.expires_at {
            return Err(ConfirmError::Expired);
        }
        let sig = Signature::from_slice(&approval.signature).map_err(|_| ConfirmError::BadSignature)?;
        self.confirmer.verify(&signed(&p.bytes, approval.decision), &sig).map_err(|_| ConfirmError::BadSignature)?;
        let p = self.pending.remove(&approval.request_id).expect("checked");
        self.decided.insert(approval.request_id, approval.decision);
        Ok(Verified { request: p.request, decision: approval.decision })
    }
}

/// Verifies an OS signature on request bytes (what the confirmer app does first).
pub fn verify_os_signature(os: &VerifyingKey, request_bytes: &[u8], signature: &[u8; 64]) -> bool {
    Signature::from_slice(signature).is_ok_and(|s| os.verify(request_bytes, &s).is_ok())
}

/// A software confirmer for tests and development (SPEC §12.7): a key in memory, approving
/// whatever it is told to. Only compiled with the `dev-confirmer` feature.
#[cfg(feature = "dev-confirmer")]
pub struct DevConfirmer {
    key: SigningKey,
}

#[cfg(feature = "dev-confirmer")]
impl DevConfirmer {
    pub fn new(secret: [u8; 32]) -> Result<DevConfirmer, ConfirmError> {
        Ok(DevConfirmer { key: SigningKey::from_bytes(&secret.into()).map_err(|_| ConfirmError::BadKey)? })
    }

    pub fn public_key(&self) -> VerifyingKey {
        *self.key.verifying_key()
    }

    pub fn decide(&self, request_bytes: &[u8], request_id: Ulid, decision: Decision) -> Approval {
        let sig: Signature = self.key.sign(&signed(request_bytes, decision));
        Approval { request_id, decision, signature: sig.to_bytes().into() }
    }
}
