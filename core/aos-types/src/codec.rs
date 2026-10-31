//! Mapping between model types and CBOR.
//!
//! Conventions for system-defined structures:
//! - structures are CBOR maps with text keys;
//! - an absent optional value is an absent key (CBOR `null` is never used);
//! - decoding rejects unknown and missing keys;
//! - [`from_bytes`] additionally requires that re-encoding the decoded value reproduces the
//!   input, so set-valued fields cannot be reordered to produce a second encoding.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::cbor::{self, Cbor, CborMap, DecodeError};

pub trait ToCbor {
    fn to_cbor(&self) -> Cbor;
}

pub trait FromCbor: Sized {
    fn from_cbor(value: &Cbor) -> Result<Self, FormatError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatError {
    Cbor(DecodeError),
    MissingKey(&'static str),
    UnknownKey(String),
    /// The item has the wrong CBOR type; the payload names what was expected.
    WrongType(&'static str),
    /// The item has the right CBOR type but an invalid value.
    InvalidValue(&'static str),
    /// Valid, but not the canonical encoding of the decoded value.
    NotCanonical,
}

impl From<DecodeError> for FormatError {
    fn from(e: DecodeError) -> FormatError {
        FormatError::Cbor(e)
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Deterministic encoding of `value`.
pub fn to_bytes<T: ToCbor + ?Sized>(value: &T) -> Vec<u8> {
    cbor::encode(&value.to_cbor())
}

/// Strict decoding: the bytes must be the deterministic encoding of the decoded value.
pub fn from_bytes<T: FromCbor + ToCbor>(bytes: &[u8]) -> Result<T, FormatError> {
    let value = T::from_cbor(&cbor::decode(bytes)?)?;
    if to_bytes(&value) != bytes {
        return Err(FormatError::NotCanonical);
    }
    Ok(value)
}

/// Builds a structure map.
#[derive(Default)]
pub struct MapBuilder(CborMap);

impl MapBuilder {
    pub fn new() -> MapBuilder {
        MapBuilder(CborMap::new())
    }

    pub fn put(mut self, key: &str, value: Cbor) -> MapBuilder {
        self.0.insert(Cbor::text(key), value);
        self
    }

    pub fn put_opt(self, key: &str, value: Option<Cbor>) -> MapBuilder {
        match value {
            Some(v) => self.put(key, v),
            None => self,
        }
    }

    pub fn build(self) -> Cbor {
        Cbor::Map(self.0)
    }
}

/// Reads a structure map, tracking which keys were consumed.
pub struct MapReader<'a> {
    map: &'a CborMap,
    seen: Vec<&'static str>,
}

impl<'a> MapReader<'a> {
    pub fn new(value: &'a Cbor, what: &'static str) -> Result<MapReader<'a>, FormatError> {
        let map = value.as_map().ok_or(FormatError::WrongType(what))?;
        Ok(MapReader { map, seen: Vec::new() })
    }

    pub fn opt(&mut self, key: &'static str) -> Option<&'a Cbor> {
        self.seen.push(key);
        self.map.get_str(key)
    }

    pub fn req(&mut self, key: &'static str) -> Result<&'a Cbor, FormatError> {
        self.opt(key).ok_or(FormatError::MissingKey(key))
    }

    pub fn finish(self) -> Result<(), FormatError> {
        for (key, _) in self.map.iter() {
            match key.as_text() {
                Some(k) if self.seen.contains(&k) => {}
                Some(k) => return Err(FormatError::UnknownKey(String::from(k))),
                None => return Err(FormatError::WrongType("text map key")),
            }
        }
        Ok(())
    }
}

pub fn text<'a>(value: &'a Cbor, what: &'static str) -> Result<&'a str, FormatError> {
    value.as_text().ok_or(FormatError::WrongType(what))
}

pub fn uint(value: &Cbor, what: &'static str) -> Result<u64, FormatError> {
    value.as_u64().ok_or(FormatError::WrongType(what))
}

pub fn int(value: &Cbor, what: &'static str) -> Result<i64, FormatError> {
    match value {
        Cbor::Unsigned(_) | Cbor::Negative(_) => value.as_i64().ok_or(FormatError::InvalidValue(what)),
        _ => Err(FormatError::WrongType(what)),
    }
}

pub fn boolean(value: &Cbor, what: &'static str) -> Result<bool, FormatError> {
    value.as_bool().ok_or(FormatError::WrongType(what))
}

pub fn array<'a>(value: &'a Cbor, what: &'static str) -> Result<&'a [Cbor], FormatError> {
    value.as_array().ok_or(FormatError::WrongType(what))
}

pub fn map<'a>(value: &'a Cbor, what: &'static str) -> Result<&'a CborMap, FormatError> {
    value.as_map().ok_or(FormatError::WrongType(what))
}

/// A map from text keys, in deterministic order.
pub fn text_map<'a, V: 'a, I>(entries: I, f: impl Fn(&V) -> Cbor) -> Cbor
where
    I: IntoIterator<Item = (&'a String, &'a V)>,
{
    Cbor::Map(entries.into_iter().map(|(k, v)| (Cbor::Text(k.clone()), f(v))).collect())
}
