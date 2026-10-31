//! Type declarations, object validation and type evolution (SPEC §6.2, §6.5).

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use core::{fmt, str::FromStr};

use crate::cbor::Cbor;
use crate::codec::{self, FormatError, FromCbor, MapBuilder, MapReader, ToCbor};
use crate::object::Object;
use crate::value::{Finite, Value, parse_decimal};

/// `namespace/Name`, e.g. `ml/DatasetVersion`. Namespace: `[a-z][a-z0-9_]{0,31}`;
/// name: `[A-Z][A-Za-z0-9]{0,63}`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TypeName {
    namespace: String,
    name: String,
}

impl TypeName {
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for TypeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

impl FromStr for TypeName {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<TypeName, FormatError> {
        let bad = FormatError::InvalidValue("type name");
        let (ns, name) = s.split_once('/').ok_or(bad.clone())?;
        let ns_ok = matches!(ns.as_bytes(), [first, rest @ ..]
            if first.is_ascii_lowercase() && rest.len() < 32
                && rest.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'));
        let name_ok = matches!(name.as_bytes(), [first, rest @ ..]
            if first.is_ascii_uppercase() && rest.len() < 64 && rest.iter().all(u8::is_ascii_alphanumeric));
        if !(ns_ok && name_ok) {
            return Err(bad);
        }
        Ok(TypeName { namespace: String::from(ns), name: String::from(name) })
    }
}

/// A type at one major version: `ml/DatasetVersion@1`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TypeId {
    pub name: TypeName,
    /// ≥ 1.
    pub major: u32,
}

impl fmt::Display for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.major)
    }
}

impl FromStr for TypeId {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<TypeId, FormatError> {
        let bad = FormatError::InvalidValue("type id");
        let (name, major) = s.split_once('@').ok_or(bad.clone())?;
        let major = parse_decimal(major).and_then(|m| u32::try_from(m).ok()).filter(|&m| m >= 1).ok_or(bad)?;
        Ok(TypeId { name: name.parse()?, major })
    }
}

/// Field and relation names: `[a-z][a-z0-9_]{0,63}`.
pub fn is_field_name(s: &str) -> bool {
    matches!(s.as_bytes(), [first, rest @ ..]
        if first.is_ascii_lowercase() && rest.len() < 64
            && rest.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'))
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FieldKind {
    Bool,
    Int {
        min: Option<i64>,
        max: Option<i64>,
    },
    Float {
        min: Option<Finite>,
        max: Option<Finite>,
    },
    /// `max_chars` counts Unicode scalar values.
    Text {
        max_chars: Option<u32>,
    },
    Bytes {
        max_len: Option<u32>,
    },
    /// The referenced object's type is checked by the object store, which can see it.
    Ref {
        target: TypeName,
    },
    Blob,
    List(Box<FieldKind>),
    /// Text keys, homogeneous values.
    Map(Box<FieldKind>),
    Any,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FieldSpec {
    pub kind: FieldKind,
    pub required: bool,
}

/// `many` objects of another type point back at this one through their field `via`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Relation {
    pub many: TypeName,
    pub via: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ViewHint {
    /// Template such as `"{dataset.name} v{version}"`; rendered by the view layer.
    pub title: String,
    pub primary_fields: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TypeDef {
    pub id: TypeId,
    pub fields: BTreeMap<String, FieldSpec>,
    pub relations: BTreeMap<String, Relation>,
    pub view_hint: Option<ViewHint>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ValidationError {
    WrongType {
        expected: TypeId,
        found: TypeId,
    },
    MissingField(String),
    /// Undeclared data belongs in `extra`.
    UndeclaredField(String),
    KindMismatch {
        field: String,
        expected: &'static str,
        found: &'static str,
    },
    OutOfRange(String),
    TooLong(String),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DefinitionError {
    BadFieldName(String),
    /// A bound pair with `min > max`.
    EmptyRange(String),
    /// A relation name collides with a field name.
    NameClash(String),
    /// A view hint names a field the type does not declare.
    UnknownPrimaryField(String),
}

impl TypeDef {
    /// Checks the declaration itself.
    pub fn check(&self) -> Result<(), DefinitionError> {
        for (name, spec) in &self.fields {
            if !is_field_name(name) {
                return Err(DefinitionError::BadFieldName(name.clone()));
            }
            if !kind_is_satisfiable(&spec.kind) {
                return Err(DefinitionError::EmptyRange(name.clone()));
            }
        }
        for (name, rel) in &self.relations {
            if !is_field_name(name) || !is_field_name(&rel.via) {
                return Err(DefinitionError::BadFieldName(name.clone()));
            }
            if self.fields.contains_key(name) {
                return Err(DefinitionError::NameClash(name.clone()));
            }
        }
        if let Some(hint) = &self.view_hint
            && let Some(f) = hint.primary_fields.iter().find(|f| !self.fields.contains_key(*f))
        {
            return Err(DefinitionError::UnknownPrimaryField(f.clone()));
        }
        Ok(())
    }

    /// Checks `object.fields` against the declaration. `extra` is not checked.
    pub fn validate(&self, object: &Object) -> Result<(), ValidationError> {
        if object.type_id != self.id {
            return Err(ValidationError::WrongType { expected: self.id.clone(), found: object.type_id.clone() });
        }
        if let Some(name) = object.fields.keys().find(|k| !self.fields.contains_key(*k)) {
            return Err(ValidationError::UndeclaredField(name.clone()));
        }
        for (name, spec) in &self.fields {
            match object.fields.get(name) {
                Some(value) => check_value(name, &spec.kind, value)?,
                None if spec.required => return Err(ValidationError::MissingField(name.clone())),
                None => {}
            }
        }
        Ok(())
    }
}

fn kind_is_satisfiable(kind: &FieldKind) -> bool {
    match kind {
        FieldKind::Int { min: Some(lo), max: Some(hi) } => lo <= hi,
        FieldKind::Float { min: Some(lo), max: Some(hi) } => lo.get() <= hi.get(),
        FieldKind::List(k) | FieldKind::Map(k) => kind_is_satisfiable(k),
        _ => true,
    }
}

fn kind_name(kind: &FieldKind) -> &'static str {
    match kind {
        FieldKind::Bool => "bool",
        FieldKind::Int { .. } => "int",
        FieldKind::Float { .. } => "float",
        FieldKind::Text { .. } => "text",
        FieldKind::Bytes { .. } => "bytes",
        FieldKind::Ref { .. } => "ref",
        FieldKind::Blob => "blob",
        FieldKind::List(_) => "list",
        FieldKind::Map(_) => "map",
        FieldKind::Any => "any",
    }
}

impl FieldKind {
    /// Checks one value against this kind; `field` names it in the error.
    pub fn check(&self, field: &str, value: &Value) -> Result<(), ValidationError> {
        check_value(field, self, value)
    }
}

fn check_value(field: &str, kind: &FieldKind, value: &Value) -> Result<(), ValidationError> {
    let mismatch = || ValidationError::KindMismatch {
        field: String::from(field),
        expected: kind_name(kind),
        found: value.kind_name(),
    };
    let in_range = |ok: bool| if ok { Ok(()) } else { Err(ValidationError::OutOfRange(String::from(field))) };
    let short_enough = |ok: bool| if ok { Ok(()) } else { Err(ValidationError::TooLong(String::from(field))) };
    match (kind, value) {
        (FieldKind::Any, _) => Ok(()),
        (FieldKind::Bool, Value::Bool(_))
        | (FieldKind::Blob, Value::Blob(_))
        | (FieldKind::Ref { .. }, Value::Ref(_)) => Ok(()),
        (FieldKind::Int { min, max }, Value::Int(n)) => {
            in_range(min.is_none_or(|lo| *n >= lo) && max.is_none_or(|hi| *n <= hi))
        }
        (FieldKind::Float { min, max }, Value::Float(x)) => {
            let x = x.get();
            in_range(min.is_none_or(|lo| x >= lo.get()) && max.is_none_or(|hi| x <= hi.get()))
        }
        (FieldKind::Text { max_chars }, Value::Text(s)) => {
            short_enough(max_chars.is_none_or(|m| s.chars().count() <= m as usize))
        }
        (FieldKind::Bytes { max_len }, Value::Bytes(b)) => short_enough(max_len.is_none_or(|m| b.len() <= m as usize)),
        (FieldKind::List(inner), Value::List(items)) => items.iter().try_for_each(|v| check_value(field, inner, v)),
        (FieldKind::Map(inner), Value::Map(m)) => m.values().try_for_each(|v| check_value(field, inner, v)),
        _ => Err(mismatch()),
    }
}

/// How a new declaration relates to the registered one (SPEC §6.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Evolution {
    /// Same major version, only optional fields added: existing objects stay valid.
    InPlace,
    /// Higher major version: a separate type that needs a migration action.
    NewMajor,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EvolutionError {
    DifferentType,
    MajorDecreased,
    /// Within one major version only new optional fields are allowed.
    IncompatibleChange(String),
}

pub fn check_evolution(old: &TypeDef, new: &TypeDef) -> Result<Evolution, EvolutionError> {
    if old.id.name != new.id.name {
        return Err(EvolutionError::DifferentType);
    }
    if new.id.major < old.id.major {
        return Err(EvolutionError::MajorDecreased);
    }
    if new.id.major > old.id.major {
        return Ok(Evolution::NewMajor);
    }
    for (name, spec) in &old.fields {
        if new.fields.get(name) != Some(spec) {
            return Err(EvolutionError::IncompatibleChange(name.clone()));
        }
    }
    for (name, spec) in &new.fields {
        if !old.fields.contains_key(name) && spec.required {
            return Err(EvolutionError::IncompatibleChange(name.clone()));
        }
    }
    for (name, rel) in &old.relations {
        if new.relations.get(name) != Some(rel) {
            return Err(EvolutionError::IncompatibleChange(name.clone()));
        }
    }
    Ok(Evolution::InPlace)
}

fn finite_to_cbor(f: &Finite) -> Cbor {
    Cbor::Float(f.get())
}

fn finite_from_cbor(value: &Cbor, what: &'static str) -> Result<Finite, FormatError> {
    match value {
        Cbor::Float(f) => Finite::new(*f).ok_or(FormatError::InvalidValue(what)),
        _ => Err(FormatError::WrongType(what)),
    }
}

fn u32_from_cbor(value: &Cbor, what: &'static str) -> Result<u32, FormatError> {
    u32::try_from(codec::uint(value, what)?).map_err(|_| FormatError::InvalidValue(what))
}

impl ToCbor for FieldKind {
    fn to_cbor(&self) -> Cbor {
        let b = MapBuilder::new().put("kind", Cbor::text(kind_name(self)));
        match self {
            FieldKind::Bool | FieldKind::Blob | FieldKind::Any => b,
            FieldKind::Int { min, max } => b.put_opt("min", min.map(Cbor::int)).put_opt("max", max.map(Cbor::int)),
            FieldKind::Float { min, max } => {
                b.put_opt("min", min.as_ref().map(finite_to_cbor)).put_opt("max", max.as_ref().map(finite_to_cbor))
            }
            FieldKind::Text { max_chars } => b.put_opt("max_chars", max_chars.map(|m| Cbor::Unsigned(m.into()))),
            FieldKind::Bytes { max_len } => b.put_opt("max_len", max_len.map(|m| Cbor::Unsigned(m.into()))),
            FieldKind::Ref { target } => b.put("target", Cbor::Text(alloc::format!("{target}"))),
            FieldKind::List(inner) | FieldKind::Map(inner) => b.put("of", inner.to_cbor()),
        }
        .build()
    }
}

impl FromCbor for FieldKind {
    fn from_cbor(value: &Cbor) -> Result<FieldKind, FormatError> {
        let mut r = MapReader::new(value, "field kind")?;
        let kind = match codec::text(r.req("kind")?, "kind")? {
            "bool" => FieldKind::Bool,
            "blob" => FieldKind::Blob,
            "any" => FieldKind::Any,
            "int" => FieldKind::Int {
                min: r.opt("min").map(|v| codec::int(v, "min")).transpose()?,
                max: r.opt("max").map(|v| codec::int(v, "max")).transpose()?,
            },
            "float" => FieldKind::Float {
                min: r.opt("min").map(|v| finite_from_cbor(v, "min")).transpose()?,
                max: r.opt("max").map(|v| finite_from_cbor(v, "max")).transpose()?,
            },
            "text" => {
                FieldKind::Text { max_chars: r.opt("max_chars").map(|v| u32_from_cbor(v, "max_chars")).transpose()? }
            }
            "bytes" => FieldKind::Bytes { max_len: r.opt("max_len").map(|v| u32_from_cbor(v, "max_len")).transpose()? },
            "ref" => FieldKind::Ref { target: codec::text(r.req("target")?, "target")?.parse()? },
            "list" => FieldKind::List(Box::new(FieldKind::from_cbor(r.req("of")?)?)),
            "map" => FieldKind::Map(Box::new(FieldKind::from_cbor(r.req("of")?)?)),
            _ => return Err(FormatError::InvalidValue("kind")),
        };
        r.finish()?;
        Ok(kind)
    }
}

impl ToCbor for TypeDef {
    fn to_cbor(&self) -> Cbor {
        let fields = codec::text_map(&self.fields, |spec: &FieldSpec| {
            MapBuilder::new().put("kind", spec.kind.to_cbor()).put("required", Cbor::Bool(spec.required)).build()
        });
        let relations = codec::text_map(&self.relations, |rel: &Relation| {
            MapBuilder::new()
                .put("many", Cbor::Text(alloc::format!("{}", rel.many)))
                .put("via", Cbor::Text(rel.via.clone()))
                .build()
        });
        let view_hint = self.view_hint.as_ref().map(|h| {
            MapBuilder::new()
                .put("title", Cbor::Text(h.title.clone()))
                .put("primary_fields", Cbor::Array(h.primary_fields.iter().map(|f| Cbor::Text(f.clone())).collect()))
                .build()
        });
        MapBuilder::new()
            .put("type", Cbor::Text(alloc::format!("{}", self.id)))
            .put("fields", fields)
            .put("relations", relations)
            .put_opt("view_hint", view_hint)
            .build()
    }
}

impl FromCbor for TypeDef {
    fn from_cbor(value: &Cbor) -> Result<TypeDef, FormatError> {
        let mut r = MapReader::new(value, "type definition")?;
        let id: TypeId = codec::text(r.req("type")?, "type")?.parse()?;
        let mut fields = BTreeMap::new();
        for (k, v) in codec::map(r.req("fields")?, "fields")?.iter() {
            let mut fr = MapReader::new(v, "field spec")?;
            let kind = FieldKind::from_cbor(fr.req("kind")?)?;
            let required = codec::boolean(fr.req("required")?, "required")?;
            fr.finish()?;
            fields.insert(String::from(codec::text(k, "field name")?), FieldSpec { kind, required });
        }
        let mut relations = BTreeMap::new();
        for (k, v) in codec::map(r.req("relations")?, "relations")?.iter() {
            let mut rr = MapReader::new(v, "relation")?;
            let many = codec::text(rr.req("many")?, "many")?.parse()?;
            let via = String::from(codec::text(rr.req("via")?, "via")?);
            rr.finish()?;
            relations.insert(String::from(codec::text(k, "relation name")?), Relation { many, via });
        }
        let view_hint = match r.opt("view_hint") {
            Some(v) => {
                let mut hr = MapReader::new(v, "view hint")?;
                let title = String::from(codec::text(hr.req("title")?, "title")?);
                let primary_fields = codec::array(hr.req("primary_fields")?, "primary_fields")?
                    .iter()
                    .map(|f| codec::text(f, "primary field").map(String::from))
                    .collect::<Result<_, _>>()?;
                hr.finish()?;
                Some(ViewHint { title, primary_fields })
            }
            None => None,
        };
        r.finish()?;
        Ok(TypeDef { id, fields, relations, view_hint })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_bytes, to_bytes};
    use crate::object::tests::sample_object;
    use alloc::{string::ToString, vec};

    /// The `ml/DatasetVersion` declaration from SPEC §6.2.
    fn dataset_version() -> TypeDef {
        let field = |kind, required| FieldSpec { kind, required };
        let mut fields = BTreeMap::new();
        fields.insert("dataset".to_string(), field(FieldKind::Ref { target: "ml/Dataset".parse().unwrap() }, true));
        fields.insert(
            "parent".to_string(),
            field(FieldKind::Ref { target: "ml/DatasetVersion".parse().unwrap() }, false),
        );
        fields.insert("sample_count".to_string(), field(FieldKind::Int { min: Some(0), max: None }, false));
        fields.insert("note".to_string(), field(FieldKind::Text { max_chars: Some(2000) }, false));
        let mut relations = BTreeMap::new();
        relations.insert(
            "samples".to_string(),
            Relation { many: "ml/Sample".parse().unwrap(), via: "dataset_version".to_string() },
        );
        TypeDef {
            id: "ml/DatasetVersion@1".parse().unwrap(),
            fields,
            relations,
            view_hint: Some(ViewHint {
                title: "{dataset.name} v{version}".to_string(),
                primary_fields: vec!["sample_count".to_string(), "note".to_string()],
            }),
        }
    }

    #[test]
    fn names_and_ids() {
        let id: TypeId = "ml/DatasetVersion@1".parse().unwrap();
        assert_eq!(id.name.namespace(), "ml");
        assert_eq!(id.name.name(), "DatasetVersion");
        assert_eq!(id.to_string(), "ml/DatasetVersion@1");
        for bad in [
            "ml/DatasetVersion",
            "ml/DatasetVersion@0",
            "ml/DatasetVersion@01",
            "ML/Dataset@1",
            "ml/dataset@1",
            "ml@1",
            "/X@1",
            "ml/Data-set@1",
        ] {
            assert!(bad.parse::<TypeId>().is_err(), "{bad}");
        }
    }

    #[test]
    fn spec_example_declaration_is_valid() {
        dataset_version().check().unwrap();
        let t = dataset_version();
        assert_eq!(from_bytes::<TypeDef>(&to_bytes(&t)), Ok(t));
    }

    #[test]
    fn validates_objects() {
        let t = dataset_version();
        let ok = sample_object();
        assert_eq!(t.validate(&ok), Ok(()));

        let mut o = ok.clone();
        o.fields.remove("dataset");
        assert_eq!(t.validate(&o), Err(ValidationError::MissingField("dataset".to_string())));

        let mut o = ok.clone();
        o.fields.remove("note");
        assert_eq!(t.validate(&o), Ok(()), "optional fields may be absent");

        let mut o = ok.clone();
        o.fields.insert("sample_count".to_string(), Value::Int(-1));
        assert_eq!(t.validate(&o), Err(ValidationError::OutOfRange("sample_count".to_string())));

        let mut o = ok.clone();
        o.fields.insert("sample_count".to_string(), Value::text("many"));
        assert!(matches!(t.validate(&o), Err(ValidationError::KindMismatch { expected: "int", found: "text", .. })));

        let mut o = ok.clone();
        o.fields.insert("note".to_string(), Value::Text("样".repeat(2000)));
        assert_eq!(t.validate(&o), Ok(()), "limit counts characters, not bytes");
        o.fields.insert("note".to_string(), Value::Text("样".repeat(2001)));
        assert_eq!(t.validate(&o), Err(ValidationError::TooLong("note".to_string())));

        let mut o = ok.clone();
        o.fields.insert("owner".to_string(), Value::text("x"));
        assert_eq!(t.validate(&o), Err(ValidationError::UndeclaredField("owner".to_string())));
        o.fields.remove("owner");
        o.extra.insert("owner".to_string(), Value::text("x"));
        assert_eq!(t.validate(&o), Ok(()), "undeclared data lives in extra");

        let mut o = ok;
        o.type_id = "ml/DatasetVersion@2".parse().unwrap();
        assert!(matches!(t.validate(&o), Err(ValidationError::WrongType { .. })));
    }

    #[test]
    fn nested_kinds() {
        let field = |kind| FieldSpec { kind, required: true };
        let mut fields = BTreeMap::new();
        fields.insert("labels".to_string(), field(FieldKind::List(Box::new(FieldKind::Text { max_chars: Some(3) }))));
        fields.insert(
            "metrics".to_string(),
            field(FieldKind::Map(Box::new(FieldKind::Float {
                min: Some(Finite::new(0.0).unwrap()),
                max: Some(Finite::new(1.0).unwrap()),
            }))),
        );
        let t = TypeDef { id: "ml/MetricSet@1".parse().unwrap(), fields, relations: BTreeMap::new(), view_hint: None };
        t.check().unwrap();
        assert_eq!(from_bytes::<TypeDef>(&to_bytes(&t)), Ok(t.clone()));

        let mut o = sample_object();
        o.type_id = t.id.clone();
        o.fields.clear();
        o.fields.insert("labels".to_string(), Value::List(vec![Value::text("跌倒"), Value::text("lie")]));
        let mut metrics = BTreeMap::new();
        metrics.insert("map50".to_string(), Value::Float(Finite::new(0.71).unwrap()));
        o.fields.insert("metrics".to_string(), Value::Map(metrics.clone()));
        assert_eq!(t.validate(&o), Ok(()));
        metrics.insert("loss".to_string(), Value::Float(Finite::new(1.5).unwrap()));
        o.fields.insert("metrics".to_string(), Value::Map(metrics));
        assert_eq!(t.validate(&o), Err(ValidationError::OutOfRange("metrics".to_string())));
    }

    #[test]
    fn rejects_bad_declarations() {
        let mut t = dataset_version();
        t.fields.insert("Bad".to_string(), FieldSpec { kind: FieldKind::Bool, required: false });
        assert_eq!(t.check(), Err(DefinitionError::BadFieldName("Bad".to_string())));

        let mut t = dataset_version();
        t.fields.insert(
            "n".to_string(),
            FieldSpec { kind: FieldKind::Int { min: Some(2), max: Some(1) }, required: false },
        );
        assert_eq!(t.check(), Err(DefinitionError::EmptyRange("n".to_string())));

        let mut t = dataset_version();
        t.view_hint.as_mut().unwrap().primary_fields.push("missing".to_string());
        assert_eq!(t.check(), Err(DefinitionError::UnknownPrimaryField("missing".to_string())));

        let mut t = dataset_version();
        t.relations.insert("note".to_string(), Relation { many: "ml/Sample".parse().unwrap(), via: "x".to_string() });
        assert_eq!(t.check(), Err(DefinitionError::NameClash("note".to_string())));
    }

    #[test]
    fn evolution_rules() {
        let old = dataset_version();

        let mut added_optional = old.clone();
        added_optional.fields.insert("source".to_string(), FieldSpec { kind: FieldKind::Any, required: false });
        assert_eq!(check_evolution(&old, &added_optional), Ok(Evolution::InPlace));

        let mut added_required = old.clone();
        added_required.fields.insert("source".to_string(), FieldSpec { kind: FieldKind::Any, required: true });
        assert_eq!(
            check_evolution(&old, &added_required),
            Err(EvolutionError::IncompatibleChange("source".to_string()))
        );

        let mut removed = old.clone();
        removed.fields.remove("note");
        assert_eq!(check_evolution(&old, &removed), Err(EvolutionError::IncompatibleChange("note".to_string())));

        let mut loosened = old.clone();
        loosened.fields.get_mut("note").unwrap().kind = FieldKind::Text { max_chars: Some(4000) };
        assert_eq!(check_evolution(&old, &loosened), Err(EvolutionError::IncompatibleChange("note".to_string())));

        let mut new_major = removed.clone();
        new_major.id.major = 2;
        assert_eq!(check_evolution(&old, &new_major), Ok(Evolution::NewMajor));
        assert_eq!(check_evolution(&new_major, &old), Err(EvolutionError::MajorDecreased));

        let mut other = old.clone();
        other.id = "ml/Dataset@1".parse().unwrap();
        assert_eq!(check_evolution(&old, &other), Err(EvolutionError::DifferentType));

        let mut view_changed = old.clone();
        view_changed.view_hint = None;
        assert_eq!(check_evolution(&old, &view_changed), Ok(Evolution::InPlace));
    }
}
