//! Objects and provenance (SPEC §6.1, §10).

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
};
use core::{fmt, str::FromStr};

use crate::cbor::Cbor;
use crate::codec::{self, FormatError, FromCbor, MapBuilder, MapReader, ToCbor};
use crate::hash::Hash256;
use crate::types::TypeId;
use crate::ulid::Ulid;
use crate::value::{self, ObjectRef, Value};

/// Milliseconds since the Unix epoch (UTC). Rendered as RFC 3339 only at the JSON boundary.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Timestamp(pub u64);

/// A lower-case identifier: `[a-z0-9][a-z0-9._-]{0,63}`. Used for adapter names.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Name(String);

impl Name {
    pub fn new(s: &str) -> Option<Name> {
        let b = s.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 64
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'));
        ok.then(|| Name(String::from(s)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who wrote an object version (SPEC §6.1). Human edits are logged and undoable like any other.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Actor {
    User,
    Agent { task: Ulid },
    Adapter { name: Name },
    System,
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Actor::User => f.write_str("user"),
            Actor::Agent { task } => write!(f, "agent:task/{task}"),
            Actor::Adapter { name } => write!(f, "adapter:{}", name.as_str()),
            Actor::System => f.write_str("system"),
        }
    }
}

impl FromStr for Actor {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<Actor, FormatError> {
        let bad = FormatError::InvalidValue("actor");
        match s {
            "user" => Ok(Actor::User),
            "system" => Ok(Actor::System),
            _ => {
                if let Some(task) = s.strip_prefix("agent:task/") {
                    // Only the canonical upper-case form, so the text form stays unique.
                    let task = Ulid::parse(task).map_err(|_| bad.clone())?;
                    if alloc::format!("{task}") != s["agent:task/".len()..] {
                        return Err(bad);
                    }
                    Ok(Actor::Agent { task })
                } else if let Some(name) = s.strip_prefix("adapter:") {
                    Ok(Actor::Adapter { name: Name::new(name).ok_or(bad)? })
                } else {
                    Err(bad)
                }
            }
        }
    }
}

/// Whether data came from outside (SPEC §10). Ordered so that `max` is propagation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Taint {
    Clean,
    External,
}

impl Taint {
    /// Taint of an object derived from `inputs`: external if any input is.
    pub fn derived<'a>(inputs: impl IntoIterator<Item = &'a Provenance>) -> Taint {
        inputs.into_iter().map(|p| p.taint).max().unwrap_or(Taint::Clean)
    }

    fn as_str(self) -> &'static str {
        match self {
            Taint::Clean => "clean",
            Taint::External => "external",
        }
    }
}

/// Ordered from least to most sensitive, for `max_sensitivity` rules (SPEC §9.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Sensitivity {
    Public,
    Internal,
    Private,
    Secret,
}

impl Sensitivity {
    /// Default for user data (SPEC §6.1).
    pub const USER_DEFAULT: Sensitivity = Sensitivity::Private;

    fn as_str(self) -> &'static str {
        match self {
            Sensitivity::Public => "public",
            Sensitivity::Internal => "internal",
            Sensitivity::Private => "private",
            Sensitivity::Secret => "secret",
        }
    }
}

/// Where an object's data came from (SPEC §10: adapter, external identifier, fetch time).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Origin {
    Internal,
    External { adapter: Name, external_id: String, fetched_at: Timestamp },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Provenance {
    pub actor: Actor,
    pub origin: Origin,
    pub taint: Taint,
    pub derived_from: BTreeSet<ObjectRef>,
    /// Transaction that wrote this version.
    pub tx: Ulid,
}

impl Provenance {
    /// External origin implies external taint; nothing can launder it at creation.
    pub fn is_consistent(&self) -> bool {
        !matches!(self.origin, Origin::External { .. }) || self.taint == Taint::External
    }
}

/// A typed, versioned data unit (SPEC §6.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Object {
    pub id: Ulid,
    pub type_id: TypeId,
    /// 1 for a new object; incremented by every write.
    pub version: u64,
    pub fields: BTreeMap<String, Value>,
    pub blobs: BTreeSet<Hash256>,
    pub provenance: Provenance,
    pub sensitivity: Sensitivity,
    /// Fields the type does not declare (loose typing, SPEC §6.5).
    pub extra: BTreeMap<String, Value>,
}

impl Object {
    pub fn object_ref(&self) -> ObjectRef {
        ObjectRef::at(self.id, self.version)
    }

    /// SHA-256 of the deterministic encoding.
    pub fn content_hash(&self) -> Hash256 {
        Hash256::of_cbor(&self.to_cbor())
    }
}

fn parse_enum<T: Copy>(
    value: &Cbor,
    what: &'static str,
    all: &[T],
    name: impl Fn(T) -> &'static str,
) -> Result<T, FormatError> {
    let s = codec::text(value, what)?;
    all.iter().copied().find(|&t| name(t) == s).ok_or(FormatError::InvalidValue(what))
}

impl ToCbor for Origin {
    fn to_cbor(&self) -> Cbor {
        match self {
            Origin::Internal => Cbor::text("internal"),
            Origin::External { adapter, external_id, fetched_at } => MapBuilder::new()
                .put("adapter", Cbor::text(adapter.as_str()))
                .put("external_id", Cbor::Text(external_id.clone()))
                .put("fetched_at", Cbor::Unsigned(fetched_at.0))
                .build(),
        }
    }
}

impl FromCbor for Origin {
    fn from_cbor(value: &Cbor) -> Result<Origin, FormatError> {
        if let Some(s) = value.as_text() {
            return if s == "internal" { Ok(Origin::Internal) } else { Err(FormatError::InvalidValue("origin")) };
        }
        let mut r = MapReader::new(value, "origin")?;
        let adapter =
            Name::new(codec::text(r.req("adapter")?, "adapter")?).ok_or(FormatError::InvalidValue("adapter"))?;
        let external_id = String::from(codec::text(r.req("external_id")?, "external_id")?);
        let fetched_at = Timestamp(codec::uint(r.req("fetched_at")?, "fetched_at")?);
        r.finish()?;
        Ok(Origin::External { adapter, external_id, fetched_at })
    }
}

impl ToCbor for Provenance {
    fn to_cbor(&self) -> Cbor {
        MapBuilder::new()
            .put("actor", Cbor::Text(alloc::format!("{}", self.actor)))
            .put("origin", self.origin.to_cbor())
            .put("taint", Cbor::text(self.taint.as_str()))
            .put("derived_from", Cbor::Array(self.derived_from.iter().map(ToCbor::to_cbor).collect()))
            .put("tx", value::ulid_to_cbor(self.tx))
            .build()
    }
}

impl FromCbor for Provenance {
    fn from_cbor(value: &Cbor) -> Result<Provenance, FormatError> {
        let mut r = MapReader::new(value, "provenance")?;
        let actor: Actor = codec::text(r.req("actor")?, "actor")?.parse()?;
        let origin = Origin::from_cbor(r.req("origin")?)?;
        let taint = parse_enum(r.req("taint")?, "taint", &[Taint::Clean, Taint::External], Taint::as_str)?;
        let derived_from = codec::array(r.req("derived_from")?, "derived_from")?
            .iter()
            .map(ObjectRef::from_cbor)
            .collect::<Result<_, _>>()?;
        let tx = value::ulid_from_cbor(r.req("tx")?)?;
        r.finish()?;
        let p = Provenance { actor, origin, taint, derived_from, tx };
        if !p.is_consistent() {
            return Err(FormatError::InvalidValue("external origin must be tainted"));
        }
        Ok(p)
    }
}

impl ToCbor for Object {
    fn to_cbor(&self) -> Cbor {
        MapBuilder::new()
            .put("id", value::ulid_to_cbor(self.id))
            .put("type", Cbor::Text(alloc::format!("{}", self.type_id)))
            .put("version", Cbor::Unsigned(self.version))
            .put("fields", codec::text_map(&self.fields, Value::to_cbor))
            .put("blobs", Cbor::Array(self.blobs.iter().map(value::hash_to_cbor).collect()))
            .put("provenance", self.provenance.to_cbor())
            .put("sensitivity", Cbor::text(self.sensitivity.as_str()))
            .put("extra", codec::text_map(&self.extra, Value::to_cbor))
            .build()
    }
}

fn value_map(value: &Cbor, what: &'static str) -> Result<BTreeMap<String, Value>, FormatError> {
    match Value::from_cbor(value)? {
        Value::Map(m) => Ok(m),
        _ => Err(FormatError::WrongType(what)),
    }
}

impl FromCbor for Object {
    fn from_cbor(value: &Cbor) -> Result<Object, FormatError> {
        let mut r = MapReader::new(value, "object")?;
        let id = value::ulid_from_cbor(r.req("id")?)?;
        let type_id: TypeId = codec::text(r.req("type")?, "type")?.parse()?;
        let version = codec::uint(r.req("version")?, "version")?;
        if version == 0 {
            return Err(FormatError::InvalidValue("version"));
        }
        let fields = value_map(r.req("fields")?, "fields")?;
        let blobs =
            codec::array(r.req("blobs")?, "blobs")?.iter().map(value::hash_from_cbor).collect::<Result<_, _>>()?;
        let provenance = Provenance::from_cbor(r.req("provenance")?)?;
        let sensitivity = parse_enum(
            r.req("sensitivity")?,
            "sensitivity",
            &[Sensitivity::Public, Sensitivity::Internal, Sensitivity::Private, Sensitivity::Secret],
            Sensitivity::as_str,
        )?;
        let extra = value_map(r.req("extra")?, "extra")?;
        r.finish()?;
        Ok(Object { id, type_id, version, fields, blobs, provenance, sensitivity, extra })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::codec::{from_bytes, to_bytes};
    use crate::value::Finite;
    use alloc::{string::ToString, vec};

    pub(crate) fn sample_object() -> Object {
        let mut fields = BTreeMap::new();
        fields.insert("dataset".to_string(), Value::Ref(ObjectRef::latest(Ulid::from_u128(1))));
        fields.insert("sample_count".to_string(), Value::Int(48213));
        fields.insert("parent".to_string(), Value::Ref(ObjectRef::latest(Ulid::from_u128(2))));
        fields.insert("note".to_string(), Value::text("去重后"));
        Object {
            id: Ulid::parse("01JC8Z3K9Q6V2X4M7N1P0R5T8W").unwrap(),
            type_id: "ml/DatasetVersion@1".parse().unwrap(),
            version: 7,
            fields,
            blobs: [Hash256::digest(b"chunk")].into_iter().collect(),
            provenance: Provenance {
                actor: Actor::Agent { task: Ulid::from_u128(3) },
                origin: Origin::Internal,
                taint: Taint::Clean,
                derived_from: [ObjectRef::at(Ulid::from_u128(2), 6)].into_iter().collect(),
                tx: Ulid::from_u128(4),
            },
            sensitivity: Sensitivity::Internal,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn object_roundtrip() {
        let mut o = sample_object();
        o.extra.insert("score".to_string(), Value::Float(Finite::new(0.5).unwrap()));
        let bytes = to_bytes(&o);
        assert_eq!(from_bytes::<Object>(&bytes), Ok(o.clone()));
        assert_eq!(o.content_hash(), Hash256::digest(&bytes));
    }

    #[test]
    fn hash_changes_with_any_field() {
        let a = sample_object();
        let mut b = a.clone();
        b.version += 1;
        let mut c = a.clone();
        c.provenance.taint = Taint::External;
        assert_ne!(a.content_hash(), b.content_hash());
        assert_ne!(a.content_hash(), c.content_hash());
    }

    #[test]
    fn rejects_unknown_and_missing_keys() {
        let Cbor::Map(mut m) = sample_object().to_cbor() else { unreachable!() };
        m.insert(Cbor::text("owner"), Cbor::text("x"));
        let bytes = crate::cbor::encode(&Cbor::Map(m));
        assert_eq!(from_bytes::<Object>(&bytes), Err(FormatError::UnknownKey("owner".to_string())));

        let Cbor::Map(full) = sample_object().to_cbor() else { unreachable!() };
        let without: crate::cbor::CborMap = full
            .iter()
            .filter(|(k, _)| k.as_text() != Some("sensitivity"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let bytes = crate::cbor::encode(&Cbor::Map(without));
        assert_eq!(from_bytes::<Object>(&bytes), Err(FormatError::MissingKey("sensitivity")));
    }

    #[test]
    fn set_fields_have_one_encoding() {
        // Two blobs in non-canonical order: valid CBOR, but not the object's canonical form.
        let o = sample_object();
        let mut hashes: alloc::vec::Vec<Cbor> =
            [Hash256::digest(b"a"), Hash256::digest(b"b")].iter().map(value::hash_to_cbor).collect();
        hashes.sort_by_key(|h| core::cmp::Reverse(crate::cbor::encode(h)));
        let Cbor::Map(mut m) = o.to_cbor() else { unreachable!() };
        m.insert(Cbor::text("blobs"), Cbor::Array(hashes));
        let bytes = crate::cbor::encode(&Cbor::Map(m));
        assert_eq!(from_bytes::<Object>(&bytes), Err(FormatError::NotCanonical));
    }

    #[test]
    fn external_origin_cannot_be_clean() {
        let mut o = sample_object();
        o.provenance.origin = Origin::External {
            adapter: Name::new("minio").unwrap(),
            external_id: "s3://bucket/key".to_string(),
            fetched_at: Timestamp(1_700_000_000_000),
        };
        let bytes = to_bytes(&o);
        assert_eq!(from_bytes::<Object>(&bytes), Err(FormatError::InvalidValue("external origin must be tainted")));
        o.provenance.taint = Taint::External;
        assert_eq!(from_bytes::<Object>(&to_bytes(&o)), Ok(o));
    }

    #[test]
    fn taint_propagates() {
        let clean = sample_object().provenance;
        let mut external = clean.clone();
        external.taint = Taint::External;
        assert_eq!(Taint::derived([&clean, &clean]), Taint::Clean);
        assert_eq!(Taint::derived([&clean, &external]), Taint::External);
        assert_eq!(Taint::derived(vec![]), Taint::Clean);
    }

    #[test]
    fn actor_text_form() {
        let task = Ulid::parse("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        for a in
            [Actor::User, Actor::System, Actor::Agent { task }, Actor::Adapter { name: Name::new("feishu").unwrap() }]
        {
            assert_eq!(a.to_string().parse::<Actor>(), Ok(a));
        }
        let lower = alloc::format!("agent:task/{}", task.to_string().to_lowercase());
        assert!(lower.parse::<Actor>().is_err());
        assert!("adapter:Bad".parse::<Actor>().is_err());
        assert!("root".parse::<Actor>().is_err());
    }
}
