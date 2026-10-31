//! The two small expression languages of action declarations (SPEC §8.1).
//!
//! Preconditions: `exists(<input>)` or `<operand> <cmp> <literal>`, where an operand is a
//! value input (`threshold`) or a field of the object a ref input names
//! (`version.sample_count`). Bound to concrete inputs they become `Predicate`s, which the
//! store logs and re-evaluates at commit.
//!
//! Cost: a sum of terms `<number>`, `<operand>` or `<number> * <operand>`, in CPU seconds.

use alloc::{string::String, vec::Vec};

use aos_branch::{Cmp, Lookup, Predicate};
use aos_types::{Finite, Value};

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Number(f64),
    Str(String),
    Dot,
    Star,
    Plus,
    LParen,
    RParen,
    Cmp(Cmp),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExprError(pub &'static str);

fn tokenize(s: &str) -> Result<Vec<Tok>, ExprError> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' => i += 1,
            b'.' if !b.get(i + 1).is_some_and(u8::is_ascii_digit) => {
                out.push(Tok::Dot);
                i += 1;
            }
            b'*' => {
                out.push(Tok::Star);
                i += 1;
            }
            b'+' => {
                out.push(Tok::Plus);
                i += 1;
            }
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b'=' | b'!' | b'<' | b'>' => {
                let two = b.get(i + 1) == Some(&b'=');
                let cmp = match (c, two) {
                    (b'=', true) => Cmp::Eq,
                    (b'!', true) => Cmp::Ne,
                    (b'<', true) => Cmp::Le,
                    (b'>', true) => Cmp::Ge,
                    (b'<', false) => Cmp::Lt,
                    (b'>', false) => Cmp::Gt,
                    _ => return Err(ExprError("expected a comparison")),
                };
                out.push(Tok::Cmp(cmp));
                i += if two { 2 } else { 1 };
            }
            b'"' => {
                let end = b[i + 1..].iter().position(|&x| x == b'"').ok_or(ExprError("unterminated string"))?;
                out.push(Tok::Str(String::from(&s[i + 1..i + 1 + end])));
                i += end + 2;
            }
            b'0'..=b'9' | b'-' | b'.' => {
                let start = i;
                i += 1;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.' || b[i] == b'e' || b[i] == b'-') {
                    i += 1;
                }
                out.push(Tok::Number(s[start..i].parse().map_err(|_| ExprError("bad number"))?));
            }
            b'a'..=b'z' | b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_lowercase() || b[i].is_ascii_digit() || b[i] == b'_') {
                    i += 1;
                }
                out.push(Tok::Ident(String::from(&s[start..i])));
            }
            _ => return Err(ExprError("unexpected character")),
        }
    }
    Ok(out)
}

/// `input` or `input.field`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    pub input: String,
    pub field: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Precondition {
    Exists(String),
    Compare(Operand, Cmp, Value),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cost {
    /// (factor, operand); `None` operand is a constant term.
    pub terms: Vec<(f64, Option<Operand>)>,
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn operand(&mut self, first: String) -> Result<Operand, ExprError> {
        if self.peek() == Some(&Tok::Dot) {
            self.pos += 1;
            match self.next() {
                Some(Tok::Ident(f)) => Ok(Operand { input: first, field: Some(f) }),
                _ => Err(ExprError("expected a field name after '.'")),
            }
        } else {
            Ok(Operand { input: first, field: None })
        }
    }

    fn done(&self) -> Result<(), ExprError> {
        if self.pos == self.toks.len() { Ok(()) } else { Err(ExprError("trailing input")) }
    }
}

fn literal(t: Option<Tok>) -> Result<Value, ExprError> {
    match t {
        Some(Tok::Number(n)) if n.abs() < 9.0e15 && (n as i64) as f64 == n => Ok(Value::Int(n as i64)),
        Some(Tok::Number(n)) => Ok(Value::Float(Finite::new(n).ok_or(ExprError("number out of range"))?)),
        Some(Tok::Str(s)) => Ok(Value::Text(s)),
        Some(Tok::Ident(i)) if i == "true" => Ok(Value::Bool(true)),
        Some(Tok::Ident(i)) if i == "false" => Ok(Value::Bool(false)),
        _ => Err(ExprError("expected a literal")),
    }
}

pub fn parse_precondition(s: &str) -> Result<Precondition, ExprError> {
    let mut p = Parser { toks: tokenize(s)?, pos: 0 };
    let Some(Tok::Ident(first)) = p.next() else { return Err(ExprError("expected an input name")) };
    let pre = if first == "exists" && p.peek() == Some(&Tok::LParen) {
        p.pos += 1;
        let Some(Tok::Ident(input)) = p.next() else { return Err(ExprError("expected an input name")) };
        if p.next() != Some(Tok::RParen) {
            return Err(ExprError("expected ')'"));
        }
        Precondition::Exists(input)
    } else {
        let operand = p.operand(first)?;
        let Some(Tok::Cmp(cmp)) = p.next() else { return Err(ExprError("expected a comparison")) };
        Precondition::Compare(operand, cmp, literal(p.next())?)
    };
    p.done()?;
    Ok(pre)
}

pub fn parse_cost(s: &str) -> Result<Cost, ExprError> {
    let mut p = Parser { toks: tokenize(s)?, pos: 0 };
    let mut terms = Vec::new();
    loop {
        let term = match p.next() {
            Some(Tok::Number(n)) if p.peek() == Some(&Tok::Star) => {
                p.pos += 1;
                let Some(Tok::Ident(i)) = p.next() else { return Err(ExprError("expected an operand after '*'")) };
                (n, Some(p.operand(i)?))
            }
            Some(Tok::Number(n)) => (n, None),
            Some(Tok::Ident(i)) => (1.0, Some(p.operand(i)?)),
            _ => return Err(ExprError("expected a cost term")),
        };
        terms.push(term);
        match p.next() {
            Some(Tok::Plus) => continue,
            None => break,
            _ => return Err(ExprError("expected '+'")),
        }
    }
    Ok(Cost { terms })
}

/// Always-true and always-false predicates.
pub fn constant(b: bool) -> Predicate {
    if b { Predicate::All(Vec::new()) } else { Predicate::Any(Vec::new()) }
}

/// A numeric value: an int or float input, or a numeric field of a referenced object.
pub fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Int(n) => Some(*n as f64),
        Value::Float(f) => Some(f.get()),
        _ => None,
    }
}

impl Cost {
    /// CPU seconds, given how operands resolve.
    pub fn eval(&self, resolve: impl Fn(&Operand) -> Option<f64>) -> Option<f64> {
        self.terms.iter().map(|(k, op)| Some(k * op.as_ref().map_or(Some(1.0), &resolve)?)).sum()
    }
}

/// Resolves `input.field` through a view (for cost estimates).
pub fn field_number(view: &impl Lookup, id: aos_types::Ulid, field: &str) -> Option<f64> {
    number(view.object(id)?.fields.get(field)?)
}
