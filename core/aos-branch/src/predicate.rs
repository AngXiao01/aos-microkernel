//! Preconditions: predicates over objects, evaluated when a transaction is applied and
//! again when its branch is committed (SPEC §7.5, §8.3). They are data, so they can be
//! logged and re-evaluated after a rebase.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::cmp::Ordering;

use aos_types::cbor::Cbor;
use aos_types::codec::{FormatError, FromCbor, ToCbor};
use aos_types::{Object, Ulid, Value};

use crate::codec::{MapBuilder, MapReader, text, uint, ulid_from, ulid_to};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Predicate {
    All(Vec<Predicate>),
    Any(Vec<Predicate>),
    Not(Box<Predicate>),
    /// The object exists and is not deleted.
    Exists(Ulid),
    /// The object's current version (a deleted object keeps its tombstone version).
    VersionIs(Ulid, u64),
    /// `object.fields[field] cmp value`; false if the object or the field is missing, or
    /// the values are not comparable.
    Field {
        object: Ulid,
        field: String,
        cmp: Cmp,
        value: Value,
    },
}

/// Read access to a consistent view of the object graph.
pub trait Lookup {
    /// The live object, `None` if absent or deleted.
    fn object(&self, id: Ulid) -> Option<&Object>;
    /// The latest version, counting tombstones; `None` if the object never existed.
    fn version(&self, id: Ulid) -> Option<u64>;
}

impl Predicate {
    pub fn eval(&self, view: &impl Lookup) -> bool {
        match self {
            Predicate::All(ps) => ps.iter().all(|p| p.eval(view)),
            Predicate::Any(ps) => ps.iter().any(|p| p.eval(view)),
            Predicate::Not(p) => !p.eval(view),
            Predicate::Exists(id) => view.object(*id).is_some(),
            Predicate::VersionIs(id, v) => view.version(*id) == Some(*v),
            Predicate::Field { object, field, cmp, value } => view
                .object(*object)
                .and_then(|o| o.fields.get(field))
                .is_some_and(|actual| compare(actual, *cmp, value)),
        }
    }
}

fn order(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => Some(x.cmp(y)),
        (Value::Float(x), Value::Float(y)) => x.get().partial_cmp(&y.get()),
        (Value::Int(x), Value::Float(y)) => (*x as f64).partial_cmp(&y.get()),
        (Value::Float(x), Value::Int(y)) => x.get().partial_cmp(&(*y as f64)),
        (Value::Text(x), Value::Text(y)) => Some(x.cmp(y)),
        (Value::Bool(x), Value::Bool(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

/// The comparison rules predicates use: numbers compare across int and float, text and
/// booleans by order, everything else only by equality.
pub fn compare(actual: &Value, cmp: Cmp, expected: &Value) -> bool {
    match cmp {
        Cmp::Eq => actual == expected || order(actual, expected) == Some(Ordering::Equal),
        Cmp::Ne => !(actual == expected || order(actual, expected) == Some(Ordering::Equal)),
        Cmp::Lt => order(actual, expected) == Some(Ordering::Less),
        Cmp::Le => matches!(order(actual, expected), Some(Ordering::Less | Ordering::Equal)),
        Cmp::Gt => order(actual, expected) == Some(Ordering::Greater),
        Cmp::Ge => matches!(order(actual, expected), Some(Ordering::Greater | Ordering::Equal)),
    }
}

const CMPS: [(Cmp, &str); 6] =
    [(Cmp::Eq, "eq"), (Cmp::Ne, "ne"), (Cmp::Lt, "lt"), (Cmp::Le, "le"), (Cmp::Gt, "gt"), (Cmp::Ge, "ge")];

impl ToCbor for Predicate {
    fn to_cbor(&self) -> Cbor {
        let list = |ps: &[Predicate]| Cbor::Array(ps.iter().map(ToCbor::to_cbor).collect());
        match self {
            Predicate::All(ps) => MapBuilder::new().put("all", list(ps)),
            Predicate::Any(ps) => MapBuilder::new().put("any", list(ps)),
            Predicate::Not(p) => MapBuilder::new().put("not", p.to_cbor()),
            Predicate::Exists(id) => MapBuilder::new().put("exists", ulid_to(*id)),
            Predicate::VersionIs(id, v) => MapBuilder::new().put(
                "version_is",
                MapBuilder::new().put("id", ulid_to(*id)).put("version", Cbor::Unsigned(*v)).build(),
            ),
            Predicate::Field { object, field, cmp, value } => {
                let name = CMPS.iter().find(|(c, _)| c == cmp).map_or("eq", |(_, n)| n);
                MapBuilder::new().put(
                    "field",
                    MapBuilder::new()
                        .put("id", ulid_to(*object))
                        .put("name", Cbor::Text(field.clone()))
                        .put("cmp", Cbor::text(name))
                        .put("value", value.to_cbor())
                        .build(),
                )
            }
        }
        .build()
    }
}

impl FromCbor for Predicate {
    fn from_cbor(value: &Cbor) -> Result<Predicate, FormatError> {
        let map = value.as_map().ok_or(FormatError::WrongType("predicate"))?;
        let (key, body) = match map.iter().next() {
            Some((k, v)) if map.len() == 1 => (text(k, "predicate kind")?, v),
            _ => return Err(FormatError::InvalidValue("predicate")),
        };
        let list = |v: &Cbor| -> Result<Vec<Predicate>, FormatError> {
            v.as_array().ok_or(FormatError::WrongType("predicate list"))?.iter().map(Predicate::from_cbor).collect()
        };
        Ok(match key {
            "all" => Predicate::All(list(body)?),
            "any" => Predicate::Any(list(body)?),
            "not" => Predicate::Not(Box::new(Predicate::from_cbor(body)?)),
            "exists" => Predicate::Exists(ulid_from(body)?),
            "version_is" => {
                let mut r = MapReader::new(body, "version_is")?;
                let p = Predicate::VersionIs(ulid_from(r.req("id")?)?, uint(r.req("version")?, "version")?);
                r.finish()?;
                p
            }
            "field" => {
                let mut r = MapReader::new(body, "field predicate")?;
                let object = ulid_from(r.req("id")?)?;
                let field = String::from(text(r.req("name")?, "name")?);
                let cmp_name = text(r.req("cmp")?, "cmp")?;
                let cmp = CMPS
                    .iter()
                    .find(|(_, n)| *n == cmp_name)
                    .map(|(c, _)| *c)
                    .ok_or(FormatError::InvalidValue("cmp"))?;
                let value = Value::from_cbor(r.req("value")?)?;
                r.finish()?;
                Predicate::Field { object, field, cmp, value }
            }
            _ => return Err(FormatError::InvalidValue("predicate kind")),
        })
    }
}
