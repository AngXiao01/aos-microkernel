//! Capability tokens (SPEC §9.1): task-scoped, expiring, budgeted and only ever attenuated.
//!
//! The [`Authority`] (inside the TCB's Capability Service) holds the signing key, so no
//! component outside it can mint a token; it signs every token it issues (ECDSA P-256 over
//! the deterministic CBOR encoding) and keeps the derivation tree for budgets and revocation.
//! - Derivation only attenuates: rights, object scope, limits, egress channels and expiry
//!   of a child are each within its parent's. Agents cannot derive at all.
//! - Spending is charged to the token and every ancestor, so siblings together cannot
//!   overspend their parent.
//! - Revoking a token revokes its whole subtree.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use core::fmt;

use aos_types::cbor::Cbor;
use aos_types::codec::{self, FormatError, FromCbor, MapBuilder, MapReader, ToCbor};
use aos_types::value::{ulid_from_cbor, ulid_to_cbor};
use aos_types::{Actor, Timestamp, TypeName, Ulid};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// `cap:<ULID>`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CapId(pub Ulid);

impl fmt::Display for CapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cap:{}", self.0)
    }
}

/// An exact name, or a prefix ending in `*`: `ml.dataset.*`, `deliver:*`, `*`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Pattern(String);

impl Pattern {
    /// `None` if `*` appears anywhere but at the end.
    pub fn new(s: &str) -> Option<Pattern> {
        let star = s.find('*');
        (!s.is_empty() && star.is_none_or(|i| i == s.len() - 1)).then(|| Pattern(String::from(s)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn prefix(&self) -> Option<&str> {
        self.0.strip_suffix('*')
    }

    pub fn matches(&self, name: &str) -> bool {
        match self.prefix() {
            Some(p) => name.starts_with(p),
            None => self.0 == name,
        }
    }

    /// Everything `other` matches, `self` matches too.
    pub fn covers(&self, other: &Pattern) -> bool {
        match (self.prefix(), other.prefix()) {
            (Some(p), Some(q)) => q.starts_with(p),
            (Some(p), None) => other.0.starts_with(p),
            (None, Some(_)) => false,
            (None, None) => self.0 == other.0,
        }
    }
}

/// Budgets. CPU and GPU in milliseconds, money in fen (0.01 CNY), steps in action calls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub cpu_ms: u64,
    pub gpu_ms: u64,
    pub money_fen: u64,
    pub steps: u64,
}

impl Limits {
    fn fields(self) -> [u64; 4] {
        [self.cpu_ms, self.gpu_ms, self.money_fen, self.steps]
    }

    pub fn within(self, other: Limits) -> bool {
        self.fields().iter().zip(other.fields()).all(|(a, b)| *a <= b)
    }

    fn plus(self, other: Limits) -> Option<Limits> {
        Some(Limits {
            cpu_ms: self.cpu_ms.checked_add(other.cpu_ms)?,
            gpu_ms: self.gpu_ms.checked_add(other.gpu_ms)?,
            money_fen: self.money_fen.checked_add(other.money_fen)?,
            steps: self.steps.checked_add(other.steps)?,
        })
    }

    fn minus(self, other: Limits) -> Limits {
        Limits {
            cpu_ms: self.cpu_ms.saturating_sub(other.cpu_ms),
            gpu_ms: self.gpu_ms.saturating_sub(other.gpu_ms),
            money_fen: self.money_fen.saturating_sub(other.money_fen),
            steps: self.steps.saturating_sub(other.steps),
        }
    }
}

/// What a token grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub subject: Actor,
    /// Action capability names the holder may invoke (`ml.dataset.*`).
    pub rights: BTreeSet<Pattern>,
    /// Per type, the only objects of that type the holder may operate on; types not listed
    /// are unrestricted.
    pub scope: BTreeMap<TypeName, BTreeSet<Ulid>>,
    pub limits: Limits,
    /// Egress channels the holder may create intents for (`model:default`, `compute:*`).
    pub egress: BTreeSet<Pattern>,
    pub expires_at: Timestamp,
}

impl Spec {
    /// `self` grants nothing `parent` does not.
    pub fn within(&self, parent: &Spec) -> bool {
        let rights = self.rights.iter().all(|r| parent.rights.iter().any(|p| p.covers(r)));
        let egress = self.egress.iter().all(|c| parent.egress.iter().any(|p| p.covers(c)));
        let scope =
            parent.scope.iter().all(|(t, allowed)| self.scope.get(t).is_some_and(|mine| mine.is_subset(allowed)));
        rights && egress && scope && self.limits.within(parent.limits) && self.expires_at <= parent.expires_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub id: CapId,
    pub parent: Option<CapId>,
    pub issued_at: Timestamp,
    pub spec: Spec,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapError {
    BadKey,
    UnknownToken(CapId),
    DuplicateId(CapId),
    BadSignature,
    Revoked(CapId),
    Expired,
    /// The requested child is not an attenuation of its parent.
    NotAttenuated,
    /// Agents cannot derive tokens (SPEC §9.1).
    IssuerNotAllowed,
    /// No right covers the action's capability name.
    NoRight,
    /// An object is outside the token's scope.
    OutOfScope(Ulid),
    EgressNotAllowed,
    /// The charge would exceed the budget of this token (or an ancestor).
    BudgetExhausted(CapId),
}

struct Entry {
    token: Token,
    revoked: bool,
    spent: Limits,
}

pub struct Authority {
    key: SigningKey,
    tokens: BTreeMap<CapId, Entry>,
}

impl Authority {
    /// `secret` is the P-256 private scalar (from the platform's sealed key store).
    pub fn new(secret: [u8; 32]) -> Result<Authority, CapError> {
        let key = SigningKey::from_bytes(&secret.into()).map_err(|_| CapError::BadKey)?;
        Ok(Authority { key, tokens: BTreeMap::new() })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.key.verifying_key()
    }

    fn sign(&self, unsigned: &Token) -> [u8; 64] {
        let sig: Signature = self.key.sign(&signed_bytes(unsigned));
        sig.to_bytes().into()
    }

    fn insert(&mut self, mut token: Token) -> Result<Token, CapError> {
        if self.tokens.contains_key(&token.id) {
            return Err(CapError::DuplicateId(token.id));
        }
        token.signature = self.sign(&token);
        self.tokens.insert(token.id, Entry { token: token.clone(), revoked: false, spent: Limits::default() });
        Ok(token)
    }

    /// The user's root token: everything the user's standing policies may delegate.
    pub fn issue_root(&mut self, id: Ulid, spec: Spec, now: Timestamp) -> Result<Token, CapError> {
        self.insert(Token { id: CapId(id), parent: None, issued_at: now, spec, signature: [0; 64] })
    }

    /// Issues a child of `parent` granting `spec`, which must attenuate the parent.
    pub fn derive(
        &mut self,
        issuer: &Actor,
        parent: CapId,
        id: Ulid,
        spec: Spec,
        now: Timestamp,
    ) -> Result<Token, CapError> {
        if matches!(issuer, Actor::Agent { .. }) {
            return Err(CapError::IssuerNotAllowed);
        }
        self.check_live(parent, now)?;
        let parent_spec = &self.tokens[&parent].token.spec;
        if !spec.within(parent_spec) {
            return Err(CapError::NotAttenuated);
        }
        self.insert(Token { id: CapId(id), parent: Some(parent), issued_at: now, spec, signature: [0; 64] })
    }

    /// Registered, not revoked (nor any ancestor), not expired.
    fn check_live(&self, id: CapId, now: Timestamp) -> Result<(), CapError> {
        let mut cur = Some(id);
        while let Some(c) = cur {
            let e = self.tokens.get(&c).ok_or(CapError::UnknownToken(c))?;
            if e.revoked {
                return Err(CapError::Revoked(c));
            }
            cur = e.token.parent;
        }
        if self.tokens[&id].token.spec.expires_at <= now {
            return Err(CapError::Expired);
        }
        Ok(())
    }

    /// Checks a presented token: signed by this authority, identical to the one issued, live.
    pub fn verify(&self, token: &Token, now: Timestamp) -> Result<(), CapError> {
        let sig = Signature::from_slice(&token.signature).map_err(|_| CapError::BadSignature)?;
        self.key.verifying_key().verify(&signed_bytes(token), &sig).map_err(|_| CapError::BadSignature)?;
        let issued = self.tokens.get(&token.id).ok_or(CapError::UnknownToken(token.id))?;
        if issued.token != *token {
            return Err(CapError::BadSignature);
        }
        self.check_live(token.id, now)
    }

    /// May the holder invoke an action needing capability `right` on `objects`?
    pub fn authorize(
        &self,
        token: &Token,
        now: Timestamp,
        right: &str,
        objects: &[(TypeName, Ulid)],
    ) -> Result<(), CapError> {
        self.verify(token, now)?;
        if !token.spec.rights.iter().any(|p| p.matches(right)) {
            return Err(CapError::NoRight);
        }
        for (t, id) in objects {
            if token.spec.scope.get(t).is_some_and(|allowed| !allowed.contains(id)) {
                return Err(CapError::OutOfScope(*id));
            }
        }
        Ok(())
    }

    pub fn authorize_egress(&self, token: &Token, now: Timestamp, channel: &str) -> Result<(), CapError> {
        self.verify(token, now)?;
        if token.spec.egress.iter().any(|p| p.matches(channel)) { Ok(()) } else { Err(CapError::EgressNotAllowed) }
    }

    /// Charges `cost` to the token and all its ancestors, or to none of them.
    pub fn charge(&mut self, id: CapId, cost: Limits) -> Result<(), CapError> {
        let mut chain = Vec::new();
        let mut cur = Some(id);
        while let Some(c) = cur {
            let e = self.tokens.get(&c).ok_or(CapError::UnknownToken(c))?;
            let after = e.spent.plus(cost).ok_or(CapError::BudgetExhausted(c))?;
            if !after.within(e.token.spec.limits) {
                return Err(CapError::BudgetExhausted(c));
            }
            chain.push((c, after));
            cur = e.token.parent;
        }
        for (c, after) in chain {
            self.tokens.get_mut(&c).expect("checked").spent = after;
        }
        Ok(())
    }

    /// What is left of the token's own budget (ancestors may have less).
    pub fn remaining(&self, id: CapId) -> Option<Limits> {
        self.tokens.get(&id).map(|e| e.token.spec.limits.minus(e.spent))
    }

    /// What can still be charged to the token: the smallest remainder along its ancestry.
    pub fn available(&self, id: CapId) -> Option<Limits> {
        let mut out = self.remaining(id)?;
        let mut cur = self.tokens.get(&id)?.token.parent;
        while let Some(p) = cur {
            let e = self.tokens.get(&p)?;
            let r = e.token.spec.limits.minus(e.spent);
            out = Limits {
                cpu_ms: out.cpu_ms.min(r.cpu_ms),
                gpu_ms: out.gpu_ms.min(r.gpu_ms),
                money_fen: out.money_fen.min(r.money_fen),
                steps: out.steps.min(r.steps),
            };
            cur = e.token.parent;
        }
        Some(out)
    }

    pub fn spent(&self, id: CapId) -> Option<Limits> {
        self.tokens.get(&id).map(|e| e.spent)
    }

    /// Revokes the token and, through the ancestor check, every token derived from it.
    pub fn revoke(&mut self, id: CapId) -> Result<(), CapError> {
        self.tokens.get_mut(&id).ok_or(CapError::UnknownToken(id))?.revoked = true;
        Ok(())
    }
}

/// The bytes the signature covers: the token's encoding without the signature.
fn signed_bytes(token: &Token) -> Vec<u8> {
    let mut unsigned = token.clone();
    unsigned.signature = [0; 64];
    let Cbor::Map(mut m) = unsigned.to_cbor() else { unreachable!("tokens encode as maps") };
    m.insert(Cbor::text("signature"), Cbor::Null);
    aos_types::cbor::encode(&Cbor::Map(m))
}

fn patterns_to(set: &BTreeSet<Pattern>) -> Cbor {
    Cbor::Array(set.iter().map(|p| Cbor::text(p.as_str())).collect())
}

fn patterns_from(v: &Cbor, what: &'static str) -> Result<BTreeSet<Pattern>, FormatError> {
    codec::array(v, what)?
        .iter()
        .map(|p| Pattern::new(codec::text(p, what)?).ok_or(FormatError::InvalidValue(what)))
        .collect()
}

impl ToCbor for Limits {
    fn to_cbor(&self) -> Cbor {
        MapBuilder::new()
            .put("cpu_ms", Cbor::Unsigned(self.cpu_ms))
            .put("gpu_ms", Cbor::Unsigned(self.gpu_ms))
            .put("money_fen", Cbor::Unsigned(self.money_fen))
            .put("steps", Cbor::Unsigned(self.steps))
            .build()
    }
}

impl FromCbor for Limits {
    fn from_cbor(v: &Cbor) -> Result<Limits, FormatError> {
        let mut r = MapReader::new(v, "limits")?;
        let l = Limits {
            cpu_ms: codec::uint(r.req("cpu_ms")?, "cpu_ms")?,
            gpu_ms: codec::uint(r.req("gpu_ms")?, "gpu_ms")?,
            money_fen: codec::uint(r.req("money_fen")?, "money_fen")?,
            steps: codec::uint(r.req("steps")?, "steps")?,
        };
        r.finish()?;
        Ok(l)
    }
}

impl ToCbor for Token {
    fn to_cbor(&self) -> Cbor {
        let scope = Cbor::Map(
            self.spec
                .scope
                .iter()
                .map(|(t, ids)| {
                    (Cbor::Text(alloc::format!("{t}")), Cbor::Array(ids.iter().map(|id| ulid_to_cbor(*id)).collect()))
                })
                .collect(),
        );
        MapBuilder::new()
            .put("id", ulid_to_cbor(self.id.0))
            .put_opt("parent", self.parent.map(|p| ulid_to_cbor(p.0)))
            .put("issued_at", Cbor::Unsigned(self.issued_at.0))
            .put("subject", Cbor::Text(alloc::format!("{}", self.spec.subject)))
            .put("rights", patterns_to(&self.spec.rights))
            .put("scope", scope)
            .put("limits", self.spec.limits.to_cbor())
            .put("egress", patterns_to(&self.spec.egress))
            .put("expires_at", Cbor::Unsigned(self.spec.expires_at.0))
            .put("signature", Cbor::Bytes(self.signature.to_vec()))
            .build()
    }
}

impl FromCbor for Token {
    fn from_cbor(v: &Cbor) -> Result<Token, FormatError> {
        let mut r = MapReader::new(v, "token")?;
        let id = CapId(ulid_from_cbor(r.req("id")?)?);
        let parent = r.opt("parent").map(ulid_from_cbor).transpose()?.map(CapId);
        let issued_at = Timestamp(codec::uint(r.req("issued_at")?, "issued_at")?);
        let subject: Actor = codec::text(r.req("subject")?, "subject")?.parse()?;
        let rights = patterns_from(r.req("rights")?, "rights")?;
        let mut scope = BTreeMap::new();
        for (t, ids) in codec::map(r.req("scope")?, "scope")?.iter() {
            let t: TypeName = codec::text(t, "scope type")?.parse()?;
            let ids = codec::array(ids, "scope ids")?.iter().map(ulid_from_cbor).collect::<Result<_, _>>()?;
            scope.insert(t, ids);
        }
        let limits = Limits::from_cbor(r.req("limits")?)?;
        let egress = patterns_from(r.req("egress")?, "egress")?;
        let expires_at = Timestamp(codec::uint(r.req("expires_at")?, "expires_at")?);
        let signature: [u8; 64] = r
            .req("signature")?
            .as_bytes()
            .ok_or(FormatError::WrongType("signature"))?
            .try_into()
            .map_err(|_| FormatError::InvalidValue("signature"))?;
        r.finish()?;
        Ok(Token {
            id,
            parent,
            issued_at,
            spec: Spec { subject, rights, scope, limits, egress, expires_at },
            signature,
        })
    }
}
