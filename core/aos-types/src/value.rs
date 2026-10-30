//! Field values and object references.

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec, vec::Vec};
use core::{fmt, str::FromStr};

use crate::cbor::Cbor;
use crate::codec::{FormatError, FromCbor, ToCbor};
use crate::hash::Hash256;
use crate::ulid::Ulid;

/// CBOR tag for [`ObjectRef`] (first-come-first-served range, unregistered; see DECISIONS.md).
pub const TAG_OBJECT_REF: u64 = 0x414f_5301;
/// CBOR tag for a blob hash inside a [`Value`].
pub const TAG_BLOB: u64 = 0x414f_5302;

/// A reference to an object, optionally pinned to a version. Text form: `ID` or `ID@VERSION`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ObjectRef {
    pub id: Ulid,
    pub version: Option<u64>,
}

impl ObjectRef {
    pub fn latest(id: Ulid) -> ObjectRef {
        ObjectRef { id, version: None }
    }

    pub fn at(id: Ulid, version: u64) -> ObjectRef {
        ObjectRef { id, version: Some(version) }
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.version {
            Some(v) => write!(f, "{}@{v}", self.id),
            None => write!(f, "{}", self.id),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseRefError;

impl FromStr for ObjectRef {
    type Err = ParseRefError;

    fn from_str(s: &str) -> Result<ObjectRef, ParseRefError> {
        let (id, version) = match s.split_once('@') {
            Some((id, v)) => (id, Some(parse_decimal(v).ok_or(ParseRefError)?)),
            None => (s, None),
        };
        Ok(ObjectRef { id: Ulid::parse(id).map_err(|_| ParseRefError)?, version })
    }
}

/// Strict decimal: digits only, no sign, no leading zeros.
pub(crate) fn parse_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

impl ToCbor for ObjectRef {
    fn to_cbor(&self) -> Cbor {
        let mut parts = vec![Cbor::Bytes(self.id.to_bytes().to_vec())];
        if let Some(v) = self.version {
            parts.push(Cbor::Unsigned(v));
        }
        Cbor::Tag(TAG_OBJECT_REF, Box::new(Cbor::Array(parts)))
    }
}

impl FromCbor for ObjectRef {
    fn from_cbor(value: &Cbor) -> Result<ObjectRef, FormatError> {
        let Cbor::Tag(TAG_OBJECT_REF, inner) = value else {
            return Err(FormatError::WrongType("object reference"));
        };
        let parts = inner.as_array().ok_or(FormatError::WrongType("object reference"))?;
        let (id, version) = match parts {
            [id] => (id, None),
            [id, v] => (id, Some(v.as_u64().ok_or(FormatError::WrongType("object version"))?)),
            _ => return Err(FormatError::InvalidValue("object reference")),
        };
        Ok(ObjectRef { id: ulid_from_cbor(id)?, version })
    }
}

pub(crate) fn ulid_to_cbor(id: Ulid) -> Cbor {
    Cbor::Bytes(id.to_bytes().to_vec())
}

pub(crate) fn ulid_from_cbor(value: &Cbor) -> Result<Ulid, FormatError> {
    let bytes: [u8; 16] = value
        .as_bytes()
        .ok_or(FormatError::WrongType("ulid"))?
        .try_into()
        .map_err(|_| FormatError::InvalidValue("ulid"))?;
    Ok(Ulid::from_bytes(bytes))
}

pub(crate) fn hash_to_cbor(hash: &Hash256) -> Cbor {
    Cbor::Bytes(hash.0.to_vec())
}

pub(crate) fn hash_from_cbor(value: &Cbor) -> Result<Hash256, FormatError> {
    let bytes: [u8; 32] = value
        .as_bytes()
        .ok_or(FormatError::WrongType("sha256 hash"))?
        .try_into()
        .map_err(|_| FormatError::InvalidValue("sha256 hash"))?;
    Ok(Hash256(bytes))
}

/// A finite `f64`. Equality is bitwise, so `0.0 != -0.0`, matching their CBOR encodings.
#[derive(Clone, Copy, Debug)]
pub struct Finite(f64);

impl Finite {
    pub fn new(v: f64) -> Option<Finite> {
        v.is_finite().then_some(Finite(v))
    }

    pub fn get(self) -> f64 {
        self.0
    }
}

impl PartialEq for Finite {
    fn eq(&self, other: &Finite) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for Finite {}

/// A field value. Floats are finite and integers fit in `i64` so that every value is also
/// representable in JSON (MCP and the human interface, SPEC §18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(Finite),
    Text(String),
    Bytes(Vec<u8>),
    Ref(ObjectRef),
    Blob(Hash256),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

impl Value {
    pub fn text(s: &str) -> Value {
        Value::Text(String::from(s))
    }

    /// Short name of the value's kind, for error messages.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Text(_) => "text",
            Value::Bytes(_) => "bytes",
            Value::Ref(_) => "ref",
            Value::Blob(_) => "blob",
            Value::List(_) => "list",
            Value::Map(_) => "map",
        }
    }
}

impl ToCbor for Value {
    fn to_cbor(&self) -> Cbor {
        match self {
            Value::Null => Cbor::Null,
            Value::Bool(b) => Cbor::Bool(*b),
            Value::Int(n) => Cbor::int(*n),
            Value::Float(f) => Cbor::Float(f.get()),
            Value::Text(s) => Cbor::Text(s.clone()),
            Value::Bytes(b) => Cbor::Bytes(b.clone()),
            Value::Ref(r) => r.to_cbor(),
            Value::Blob(h) => Cbor::Tag(TAG_BLOB, Box::new(hash_to_cbor(h))),
            Value::List(items) => Cbor::Array(items.iter().map(Value::to_cbor).collect()),
            Value::Map(m) => crate::codec::text_map(m, Value::to_cbor),
        }
    }
}

impl FromCbor for Value {
    fn from_cbor(value: &Cbor) -> Result<Value, FormatError> {
        Ok(match value {
            Cbor::Null => Value::Null,
            Cbor::Bool(b) => Value::Bool(*b),
            Cbor::Unsigned(_) | Cbor::Negative(_) => {
                Value::Int(value.as_i64().ok_or(FormatError::InvalidValue("integer outside i64"))?)
            }
            Cbor::Float(f) => Value::Float(Finite::new(*f).ok_or(FormatError::InvalidValue("non-finite float"))?),
            Cbor::Text(s) => Value::Text(s.clone()),
            Cbor::Bytes(b) => Value::Bytes(b.clone()),
            Cbor::Tag(TAG_OBJECT_REF, _) => Value::Ref(ObjectRef::from_cbor(value)?),
            Cbor::Tag(TAG_BLOB, inner) => Value::Blob(hash_from_cbor(inner)?),
            Cbor::Tag(..) => return Err(FormatError::InvalidValue("unknown tag")),
            Cbor::Array(items) => Value::List(items.iter().map(Value::from_cbor).collect::<Result<_, _>>()?),
            Cbor::Map(m) => {
                let mut out = BTreeMap::new();
                for (k, v) in m.iter() {
                    let k = k.as_text().ok_or(FormatError::WrongType("text map key"))?;
                    out.insert(String::from(k), Value::from_cbor(v)?);
                }
                Value::Map(out)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_bytes, to_bytes};
    use alloc::string::ToString;

    fn id(n: u128) -> Ulid {
        Ulid::from_u128(n)
    }

    #[test]
    fn object_ref_text_form() {
        let r = ObjectRef::at(Ulid::parse("01JC8Z3K9Q6V2X4M7N1P0R5T8W").unwrap(), 7);
        assert_eq!(r.to_string(), "01JC8Z3K9Q6V2X4M7N1P0R5T8W@7");
        assert_eq!("01JC8Z3K9Q6V2X4M7N1P0R5T8W@7".parse(), Ok(r));
        assert_eq!("01JC8Z3K9Q6V2X4M7N1P0R5T8W".parse(), Ok(ObjectRef::latest(r.id)));
        for bad in
            ["01JC8Z3K9Q6V2X4M7N1P0R5T8W@", "01JC8Z3K9Q6V2X4M7N1P0R5T8W@07", "01JC8Z3K9Q6V2X4M7N1P0R5T8W@-1", "x@1"]
        {
            assert_eq!(bad.parse::<ObjectRef>(), Err(ParseRefError), "{bad}");
        }
    }

    #[test]
    fn value_roundtrip() {
        let mut m = BTreeMap::new();
        m.insert("b".to_string(), Value::Int(-5));
        m.insert("a".to_string(), Value::Float(Finite::new(0.25).unwrap()));
        let v = Value::List(vec![
            Value::Null,
            Value::Bool(true),
            Value::Int(i64::MIN),
            Value::Int(i64::MAX),
            Value::text("去重后"),
            Value::Bytes(vec![0, 1, 2]),
            Value::Ref(ObjectRef::at(id(42), 3)),
            Value::Ref(ObjectRef::latest(id(42))),
            Value::Blob(Hash256::digest(b"blob")),
            Value::Map(m),
        ]);
        assert_eq!(from_bytes::<Value>(&to_bytes(&v)), Ok(v));
    }

    #[test]
    fn value_rejects_what_json_cannot_carry() {
        assert!(Finite::new(f64::NAN).is_none());
        assert!(Finite::new(f64::INFINITY).is_none());
        let inf = crate::cbor::encode(&Cbor::Float(f64::INFINITY));
        assert_eq!(from_bytes::<Value>(&inf), Err(FormatError::InvalidValue("non-finite float")));
        let big = crate::cbor::encode(&Cbor::Unsigned(u64::MAX));
        assert_eq!(from_bytes::<Value>(&big), Err(FormatError::InvalidValue("integer outside i64")));
        let tagged = crate::cbor::encode(&Cbor::Tag(1, Box::new(Cbor::Unsigned(0))));
        assert_eq!(from_bytes::<Value>(&tagged), Err(FormatError::InvalidValue("unknown tag")));
    }

    #[test]
    fn int_and_float_stay_distinct() {
        let i = to_bytes(&Value::Int(2));
        let f = to_bytes(&Value::Float(Finite::new(2.0).unwrap()));
        assert_ne!(i, f);
        assert_eq!(from_bytes::<Value>(&f), Ok(Value::Float(Finite::new(2.0).unwrap())));
    }
}
