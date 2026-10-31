//! Action declarations (SPEC §8.1–8.2) and the host ABI actions are compiled against
//! (SPEC §8.4).
//!
//! A declaration states everything the runtime enforces: which types the action may read
//! and write, which egress channels it may use, its reversibility, preconditions, cost and
//! the capability right needed to invoke it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod abi;
pub mod expr;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use aos_branch::{Lookup, Predicate};
use aos_types::{FieldKind, TypeName, ValidationError, Value};

use expr::{ExprError, Operand, Precondition};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reversibility {
    /// A reverse transaction restores the previous state.
    Undo,
    /// Cannot be undone, but a declared compensation exists.
    Compensate,
    Irreversible,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InputSpec {
    pub kind: FieldKind,
    /// Inputs without a default are required.
    pub default: Option<Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    pub reads: BTreeSet<TypeName>,
    pub writes: BTreeSet<TypeName>,
    /// Egress channel patterns (`compute:*`).
    pub egress: BTreeSet<String>,
}

impl Effects {
    /// Writing a type implies reading it.
    pub fn may_read(&self, t: &TypeName) -> bool {
        self.reads.contains(t) || self.writes.contains(t)
    }

    pub fn may_write(&self, t: &TypeName) -> bool {
        self.writes.contains(t)
    }

    pub fn may_egress(&self, channel: &str) -> bool {
        self.egress.iter().any(|p| p.strip_suffix('*').map_or(p == channel, |prefix| channel.starts_with(prefix)))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActionDecl {
    /// Dotted name, e.g. `ml.dataset.dedupe`.
    pub name: String,
    pub version: u32,
    pub provider: String,
    pub summary: String,
    pub inputs: BTreeMap<String, InputSpec>,
    pub outputs: BTreeMap<String, FieldKind>,
    pub effects: Effects,
    pub reversibility: Reversibility,
    pub preconditions: Vec<String>,
    /// CPU seconds, e.g. `0.002 * version.sample_count`.
    pub cost: Option<String>,
    /// The capability right that allows invoking the action.
    pub capability: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeclError {
    BadName(String),
    /// Internal actions must be `undo` (SPEC §8.2).
    InternalNotUndo,
    BadInput(String),
    /// A ref input points at a type the action does not declare reading.
    UndeclaredInputType(String),
    BadExpression {
        expr: String,
        error: ExprError,
    },
    UnknownOperand(String),
    MissingCapability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindError {
    Missing(String),
    Unknown(String),
    Invalid(ValidationError),
}

/// Inputs after defaults and validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    pub values: BTreeMap<String, Value>,
}

fn is_dotted_name(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|part| {
            matches!(part.as_bytes(), [first, rest @ ..]
                if first.is_ascii_lowercase() && rest.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_'))
        })
}

impl ActionDecl {
    /// `name@version`, as logged with each transaction.
    pub fn id(&self) -> String {
        alloc::format!("{}@{}", self.name, self.version)
    }

    pub fn check(&self) -> Result<(), DeclError> {
        if !is_dotted_name(&self.name) {
            return Err(DeclError::BadName(self.name.clone()));
        }
        if self.capability.is_empty() {
            return Err(DeclError::MissingCapability);
        }
        if self.effects.egress.is_empty() && self.reversibility != Reversibility::Undo {
            return Err(DeclError::InternalNotUndo);
        }
        for (name, spec) in &self.inputs {
            if !aos_types::types::is_field_name(name) {
                return Err(DeclError::BadInput(name.clone()));
            }
            if let FieldKind::Ref { target } = &spec.kind
                && !self.effects.may_read(target)
            {
                return Err(DeclError::UndeclaredInputType(name.clone()));
            }
            if let Some(d) = &spec.default
                && spec.kind.check(name, d).is_err()
            {
                return Err(DeclError::BadInput(name.clone()));
            }
        }
        let bad = |expr: &String, error| DeclError::BadExpression { expr: expr.clone(), error };
        for p in &self.preconditions {
            match expr::parse_precondition(p).map_err(|e| bad(p, e))? {
                Precondition::Exists(input) => self.operand_kind(&Operand { input, field: None })?,
                Precondition::Compare(op, _, _) => self.operand_kind(&op)?,
            };
        }
        if let Some(c) = &self.cost {
            for (_, op) in expr::parse_cost(c).map_err(|e| bad(c, e))?.terms {
                if let Some(op) = op {
                    self.operand_kind(&op)?;
                }
            }
        }
        Ok(())
    }

    /// An operand must name an input; `input.field` needs a ref input.
    fn operand_kind(&self, op: &Operand) -> Result<&FieldKind, DeclError> {
        let spec = self.inputs.get(&op.input).ok_or_else(|| DeclError::UnknownOperand(op.input.clone()))?;
        match (&spec.kind, &op.field) {
            (FieldKind::Ref { .. }, _) | (_, None) => Ok(&spec.kind),
            _ => Err(DeclError::UnknownOperand(alloc::format!("{}.{}", op.input, op.field.as_deref().unwrap_or("")))),
        }
    }

    /// Applies defaults and checks every input against its declared kind.
    pub fn bind(&self, inputs: &BTreeMap<String, Value>) -> Result<Bound, BindError> {
        if let Some(unknown) = inputs.keys().find(|k| !self.inputs.contains_key(*k)) {
            return Err(BindError::Unknown(unknown.clone()));
        }
        let mut values = BTreeMap::new();
        for (name, spec) in &self.inputs {
            let v = inputs.get(name).or(spec.default.as_ref()).ok_or_else(|| BindError::Missing(name.clone()))?;
            spec.kind.check(name, v).map_err(BindError::Invalid)?;
            values.insert(name.clone(), v.clone());
        }
        Ok(Bound { values })
    }

    /// The objects the inputs reference, with their declared types (for scope checks).
    pub fn input_objects(&self, bound: &Bound) -> Vec<(TypeName, aos_types::ObjectRef)> {
        self.inputs
            .iter()
            .filter_map(|(name, spec)| match (&spec.kind, bound.values.get(name)) {
                (FieldKind::Ref { target }, Some(Value::Ref(r))) => Some((target.clone(), *r)),
                _ => None,
            })
            .collect()
    }

    /// The preconditions as store predicates over the bound inputs.
    pub fn compile_preconditions(&self, bound: &Bound) -> Result<Vec<Predicate>, ExprError> {
        self.preconditions
            .iter()
            .map(|p| match expr::parse_precondition(p)? {
                Precondition::Exists(input) => match bound.values.get(&input) {
                    Some(Value::Ref(r)) => Ok(Predicate::Exists(r.id)),
                    _ => Err(ExprError("exists() needs a ref input")),
                },
                Precondition::Compare(op, cmp, literal) => match (bound.values.get(&op.input), op.field) {
                    (Some(Value::Ref(r)), Some(field)) => {
                        Ok(Predicate::Field { object: r.id, field, cmp, value: literal })
                    }
                    // A value input is known now: the precondition is a constant.
                    (Some(v), None) => Ok(expr::constant(aos_branch::predicate::compare(v, cmp, &literal))),
                    _ => Err(ExprError("operand does not match the inputs")),
                },
            })
            .collect()
    }

    /// Estimated CPU seconds; 0 without a cost expression.
    pub fn estimate_cost(&self, bound: &Bound, view: &impl Lookup) -> Option<f64> {
        let Some(c) = &self.cost else { return Some(0.0) };
        expr::parse_cost(c).ok()?.eval(|op| match (bound.values.get(&op.input)?, &op.field) {
            (Value::Ref(r), Some(f)) => expr::field_number(view, r.id, f),
            (v, None) => expr::number(v),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_branch::Cmp;
    use aos_types::{Finite, ObjectRef, Ulid};
    use expr::{Operand, parse_cost, parse_precondition};

    /// `ml.dataset.dedupe` from SPEC §8.1.
    fn dedupe() -> ActionDecl {
        let version_type: TypeName = "ml/DatasetVersion".parse().unwrap();
        let mut inputs = BTreeMap::new();
        inputs.insert(
            "version".into(),
            InputSpec { kind: FieldKind::Ref { target: version_type.clone() }, default: None },
        );
        inputs.insert(
            "threshold".into(),
            InputSpec {
                kind: FieldKind::Float { min: Finite::new(0.5), max: Finite::new(1.0) },
                default: Some(Value::Float(Finite::new(0.95).unwrap())),
            },
        );
        let mut outputs = BTreeMap::new();
        outputs.insert("new_version".into(), FieldKind::Ref { target: version_type.clone() });
        let sample: TypeName = "ml/Sample".parse().unwrap();
        ActionDecl {
            name: "ml.dataset.dedupe".into(),
            version: 1,
            provider: "ml".into(),
            summary: "按感知哈希相似度去重，产出新的数据集版本".into(),
            inputs,
            outputs,
            effects: Effects {
                reads: [version_type.clone(), sample.clone()].into(),
                writes: [version_type, sample].into(),
                egress: BTreeSet::new(),
            },
            reversibility: Reversibility::Undo,
            preconditions: vec!["version.sample_count > 0".into()],
            cost: Some("0.002 * version.sample_count".into()),
            capability: "ml.dataset.write".into(),
        }
    }

    #[test]
    fn the_spec_example_declaration_checks() {
        let d = dedupe();
        d.check().unwrap();
        assert_eq!(d.id(), "ml.dataset.dedupe@1");
    }

    #[test]
    fn declaration_rules() {
        let mut d = dedupe();
        d.reversibility = Reversibility::Irreversible;
        assert_eq!(d.check(), Err(DeclError::InternalNotUndo), "internal actions must be undo (§8.2)");
        d.effects.egress.insert("deliver:*".into());
        assert_eq!(d.check(), Ok(()));

        let mut d = dedupe();
        d.effects.reads.clear();
        d.effects.writes.clear();
        assert_eq!(d.check(), Err(DeclError::UndeclaredInputType("version".into())));

        let mut d = dedupe();
        d.preconditions.push("threshold.x > 1".into());
        assert_eq!(d.check(), Err(DeclError::UnknownOperand("threshold.x".into())));

        let mut d = dedupe();
        d.cost = Some("0.002 * missing".into());
        assert_eq!(d.check(), Err(DeclError::UnknownOperand("missing".into())));

        let mut d = dedupe();
        d.name = "ML.Dedupe".into();
        assert!(matches!(d.check(), Err(DeclError::BadName(_))));
    }

    #[test]
    fn expressions_parse() {
        assert_eq!(
            parse_precondition("version.sample_count >= 10").unwrap(),
            expr::Precondition::Compare(
                Operand { input: "version".into(), field: Some("sample_count".into()) },
                Cmp::Ge,
                Value::Int(10)
            )
        );
        assert_eq!(parse_precondition("exists(version)").unwrap(), expr::Precondition::Exists("version".into()));
        assert!(matches!(
            parse_precondition("label != \"fall\"").unwrap(),
            expr::Precondition::Compare(_, Cmp::Ne, Value::Text(t)) if t == "fall"
        ));
        for bad in ["version.", "x >", "x > 1 2", "x ~ 1", "\"open"] {
            assert!(parse_precondition(bad).is_err(), "{bad}");
        }
        let c = parse_cost("1.5 + 0.002 * version.sample_count + threshold").unwrap();
        assert_eq!(c.terms.len(), 3);
        assert_eq!(c.eval(|op| Some(if op.field.is_some() { 1000.0 } else { 0.5 })), Some(1.5 + 2.0 + 0.5));
    }

    #[test]
    fn binding_applies_defaults_and_compiles_preconditions() {
        let d = dedupe();
        let id = Ulid::from_u128(5);
        let mut inputs = BTreeMap::new();
        inputs.insert("version".into(), Value::Ref(ObjectRef::latest(id)));
        let bound = d.bind(&inputs).unwrap();
        assert_eq!(bound.values.get("threshold"), Some(&Value::Float(Finite::new(0.95).unwrap())));
        assert_eq!(
            d.compile_preconditions(&bound).unwrap(),
            vec![Predicate::Field { object: id, field: "sample_count".into(), cmp: Cmp::Gt, value: Value::Int(0) }]
        );
        inputs.insert("threshold".into(), Value::Float(Finite::new(0.2).unwrap()));
        assert!(matches!(d.bind(&inputs), Err(BindError::Invalid(_))), "below the declared minimum");
        inputs.remove("version");
        inputs.remove("threshold");
        assert_eq!(d.bind(&inputs), Err(BindError::Missing("version".into())));
        inputs.insert("other".into(), Value::Int(1));
        assert_eq!(d.bind(&inputs), Err(BindError::Unknown("other".into())));

        // A precondition on a value input is decided at bind time.
        let mut d = dedupe();
        d.preconditions = vec!["threshold < 0.99".into()];
        let bound = d.bind(&BTreeMap::from([("version".to_string(), Value::Ref(ObjectRef::latest(id)))])).unwrap();
        assert_eq!(d.compile_preconditions(&bound).unwrap(), vec![expr::constant(true)]);
    }
}
