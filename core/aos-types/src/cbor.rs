//! Deterministic CBOR (RFC 8949 §4.2.1, core deterministic encoding).
//!
//! [`encode`] always produces the deterministic form: shortest-form arguments, definite
//! lengths, preferred (shortest exact) float encodings, map keys in bytewise order of their
//! encodings. [`decode`] is strict: it accepts only input that is already deterministic
//! (checked by re-encoding and comparing bytes), so every value has exactly one accepted
//! encoding. Hashes and signatures (SPEC §7.1) rely on this.

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use core::fmt;

/// Maximum nesting depth accepted by [`decode`].
pub const MAX_DEPTH: usize = 64;

const CANONICAL_NAN: [u8; 3] = [0xf9, 0x7e, 0x00];

/// A CBOR data item.
///
/// Equality is equality of deterministic encodings: all NaNs are equal to each other, and
/// `0.0 != -0.0`.
#[derive(Clone, Debug)]
pub enum Cbor {
    Unsigned(u64),
    /// The integer `-1 - n`.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(CborMap),
    Tag(u64, Box<Cbor>),
    Bool(bool),
    Null,
    Float(f64),
}

impl PartialEq for Cbor {
    fn eq(&self, other: &Self) -> bool {
        use Cbor::*;
        match (self, other) {
            (Unsigned(a), Unsigned(b)) | (Negative(a), Negative(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Text(a), Text(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            (Map(a), Map(b)) => a == b,
            (Tag(ta, a), Tag(tb, b)) => ta == tb && a == b,
            (Bool(a), Bool(b)) => a == b,
            (Null, Null) => true,
            (Float(a), Float(b)) => (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits(),
            _ => false,
        }
    }
}

impl Eq for Cbor {}

impl Cbor {
    pub fn int(n: i64) -> Cbor {
        if n >= 0 { Cbor::Unsigned(n as u64) } else { Cbor::Negative(!(n as u64)) }
    }

    pub fn text(s: &str) -> Cbor {
        Cbor::Text(String::from(s))
    }

    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Cbor::Unsigned(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Cbor::Unsigned(n) => i64::try_from(n).ok(),
            Cbor::Negative(n) => i64::try_from(n).ok().map(|n| !n),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Cbor]> {
        match self {
            Cbor::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&CborMap> {
        match self {
            Cbor::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match *self {
            Cbor::Bool(b) => Some(b),
            _ => None,
        }
    }
}

/// A map kept in deterministic order: entries are keyed by the encoding of their key, so
/// iteration order is the encoding order and duplicate keys cannot exist.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CborMap {
    entries: BTreeMap<Vec<u8>, (Cbor, Cbor)>,
}

impl CborMap {
    pub fn new() -> CborMap {
        CborMap::default()
    }

    /// Inserts an entry, returning the previous value for an equal key.
    pub fn insert(&mut self, key: Cbor, value: Cbor) -> Option<Cbor> {
        self.entries.insert(encode(&key), (key, value)).map(|(_, v)| v)
    }

    pub fn get(&self, key: &Cbor) -> Option<&Cbor> {
        self.entries.get(&encode(key)).map(|(_, v)| v)
    }

    pub fn get_str(&self, key: &str) -> Option<&Cbor> {
        let mut k = Vec::with_capacity(key.len() + 9);
        head(&mut k, 3, key.len() as u64);
        k.extend_from_slice(key.as_bytes());
        self.entries.get(&k).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&Cbor, &Cbor)> {
        self.entries.values().map(|(k, v)| (k, v))
    }
}

impl FromIterator<(Cbor, Cbor)> for CborMap {
    fn from_iter<I: IntoIterator<Item = (Cbor, Cbor)>>(iter: I) -> CborMap {
        let mut m = CborMap::new();
        for (k, v) in iter {
            m.insert(k, v);
        }
        m
    }
}

pub fn encode(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

pub fn encode_into(value: &Cbor, out: &mut Vec<u8>) {
    match value {
        Cbor::Unsigned(n) => head(out, 0, *n),
        Cbor::Negative(n) => head(out, 1, *n),
        Cbor::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Cbor::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Cbor::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Cbor::Map(m) => {
            head(out, 5, m.len() as u64);
            for (key_bytes, (_, v)) in &m.entries {
                out.extend_from_slice(key_bytes);
                encode_into(v, out);
            }
        }
        Cbor::Tag(tag, item) => {
            head(out, 6, *tag);
            encode_into(item, out);
        }
        Cbor::Bool(false) => out.push(0xf4),
        Cbor::Bool(true) => out.push(0xf5),
        Cbor::Null => out.push(0xf6),
        Cbor::Float(f) => encode_float(*f, out),
    }
}

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.extend_from_slice(&[m | 24, arg as u8]);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encode_float(v: f64, out: &mut Vec<u8>) {
    if v.is_nan() {
        out.extend_from_slice(&CANONICAL_NAN);
    } else if let Some(h) = f64_to_f16_exact(v) {
        out.push(0xf9);
        out.extend_from_slice(&h.to_be_bytes());
    } else if (v as f32) as f64 == v {
        out.push(0xfa);
        out.extend_from_slice(&(v as f32).to_bits().to_be_bytes());
    } else {
        out.push(0xfb);
        out.extend_from_slice(&v.to_bits().to_be_bytes());
    }
}

/// The binary16 encoding of a non-NaN `v`, if binary16 represents it exactly.
fn f64_to_f16_exact(v: f64) -> Option<u16> {
    let f = v as f32;
    if f as f64 != v {
        return None;
    }
    let bits = f.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exp = ((bits >> 23) & 0xff) as i32;
    let mant = bits & 0x7f_ffff;
    if exp == 0xff {
        return Some(sign | 0x7c00); // infinity (NaN is handled by the caller)
    }
    if exp == 0 {
        // ±0; binary32 subnormals are below the binary16 range.
        return if mant == 0 { Some(sign) } else { None };
    }
    let e = exp - 127;
    if (-14..=15).contains(&e) {
        if mant & 0x1fff != 0 {
            return None;
        }
        Some(sign | (((e + 15) as u16) << 10) | (mant >> 13) as u16)
    } else if (-24..=-15).contains(&e) {
        // binary16 subnormal: value = m * 2^-24.
        let full = mant | 0x80_0000;
        let shift = (-(e + 1)) as u32;
        if full & ((1 << shift) - 1) != 0 {
            return None;
        }
        Some(sign | (full >> shift) as u16)
    } else {
        None
    }
}

fn f16_to_f64(h: u16) -> f64 {
    let exp = u32::from((h >> 10) & 0x1f);
    let mant = u32::from(h & 0x3ff);
    let magnitude = match exp {
        0 => mant as f32 * (1.0 / 16_777_216.0), // mant * 2^-24, exact
        31 if mant == 0 => f32::INFINITY,
        31 => f32::NAN,
        _ => f32::from_bits(((exp + 127 - 15) << 23) | (mant << 13)),
    };
    let v = f64::from(magnitude);
    if h & 0x8000 != 0 { -v } else { v }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEnd,
    TrailingBytes,
    IndefiniteLength,
    /// Additional information 28–30, or a "break" outside an indefinite-length item.
    Reserved,
    InvalidUtf8,
    /// `undefined` or any simple value other than false/true/null.
    UnsupportedSimpleValue,
    TooDeep,
    DuplicateKey,
    /// Well-formed CBOR that is not in deterministic form.
    NotDeterministic,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Decodes exactly one deterministic data item spanning all of `bytes`.
pub fn decode(bytes: &[u8]) -> Result<Cbor, DecodeError> {
    let mut reader = Reader { bytes, pos: 0 };
    let value = reader.item(0)?;
    if reader.pos != bytes.len() {
        return Err(DecodeError::TrailingBytes);
    }
    if encode(&value) != bytes {
        return Err(DecodeError::NotDeterministic);
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8], DecodeError> {
        if len > self.remaining() as u64 {
            return Err(DecodeError::UnexpectedEnd);
        }
        let start = self.pos;
        self.pos += len as usize;
        Ok(&self.bytes[start..self.pos])
    }

    fn uint(&mut self, len: u64) -> Result<u64, DecodeError> {
        Ok(self.take(len)?.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    fn argument(&mut self, info: u8) -> Result<u64, DecodeError> {
        match info {
            0..=23 => Ok(u64::from(info)),
            24 => self.uint(1),
            25 => self.uint(2),
            26 => self.uint(4),
            27 => self.uint(8),
            28..=30 => Err(DecodeError::Reserved),
            _ => Err(DecodeError::IndefiniteLength),
        }
    }

    /// Every element takes at least one byte, which bounds allocations by the input size.
    fn count(&self, n: u64) -> Result<usize, DecodeError> {
        if n > self.remaining() as u64 { Err(DecodeError::UnexpectedEnd) } else { Ok(n as usize) }
    }

    fn item(&mut self, depth: usize) -> Result<Cbor, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError::TooDeep);
        }
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        if major == 7 {
            return self.simple_or_float(info);
        }
        let arg = self.argument(info)?;
        Ok(match major {
            0 => Cbor::Unsigned(arg),
            1 => Cbor::Negative(arg),
            2 => Cbor::Bytes(self.take(arg)?.to_vec()),
            3 => {
                let s = core::str::from_utf8(self.take(arg)?).map_err(|_| DecodeError::InvalidUtf8)?;
                Cbor::Text(String::from(s))
            }
            4 => {
                let n = self.count(arg)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Cbor::Array(items)
            }
            5 => {
                let n = self.count(arg)?;
                let mut map = CborMap::new();
                for _ in 0..n {
                    let key = self.item(depth + 1)?;
                    let value = self.item(depth + 1)?;
                    if map.insert(key, value).is_some() {
                        return Err(DecodeError::DuplicateKey);
                    }
                }
                Cbor::Map(map)
            }
            _ => Cbor::Tag(arg, Box::new(self.item(depth + 1)?)),
        })
    }

    fn simple_or_float(&mut self, info: u8) -> Result<Cbor, DecodeError> {
        Ok(match info {
            20 => Cbor::Bool(false),
            21 => Cbor::Bool(true),
            22 => Cbor::Null,
            25 => Cbor::Float(f16_to_f64(self.uint(2)? as u16)),
            26 => Cbor::Float(f64::from(f32::from_bits(self.uint(4)? as u32))),
            27 => Cbor::Float(f64::from_bits(self.uint(8)?)),
            28..=31 => return Err(DecodeError::Reserved),
            _ => return Err(DecodeError::UnsupportedSimpleValue),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn roundtrip(value: Cbor, expected_hex: &str) {
        let bytes = encode(&value);
        assert_eq!(bytes, hex(expected_hex), "encoding of {value:?}");
        assert_eq!(decode(&bytes).unwrap(), value, "decoding of {expected_hex}");
    }

    fn map(entries: Vec<(Cbor, Cbor)>) -> Cbor {
        Cbor::Map(entries.into_iter().collect())
    }

    #[test]
    fn rfc8949_appendix_a_integers() {
        roundtrip(Cbor::Unsigned(0), "00");
        roundtrip(Cbor::Unsigned(1), "01");
        roundtrip(Cbor::Unsigned(10), "0a");
        roundtrip(Cbor::Unsigned(23), "17");
        roundtrip(Cbor::Unsigned(24), "1818");
        roundtrip(Cbor::Unsigned(25), "1819");
        roundtrip(Cbor::Unsigned(100), "1864");
        roundtrip(Cbor::Unsigned(1000), "1903e8");
        roundtrip(Cbor::Unsigned(1_000_000), "1a000f4240");
        roundtrip(Cbor::Unsigned(1_000_000_000_000), "1b000000e8d4a51000");
        roundtrip(Cbor::Unsigned(u64::MAX), "1bffffffffffffffff");
        roundtrip(Cbor::Negative(u64::MAX), "3bffffffffffffffff");
        roundtrip(Cbor::int(-1), "20");
        roundtrip(Cbor::int(-10), "29");
        roundtrip(Cbor::int(-100), "3863");
        roundtrip(Cbor::int(-1000), "3903e7");
        assert_eq!(Cbor::int(i64::MIN).as_i64(), Some(i64::MIN));
        assert_eq!(Cbor::Negative(u64::MAX).as_i64(), None);
    }

    #[test]
    fn rfc8949_appendix_a_floats() {
        roundtrip(Cbor::Float(0.0), "f90000");
        roundtrip(Cbor::Float(-0.0), "f98000");
        roundtrip(Cbor::Float(1.0), "f93c00");
        roundtrip(Cbor::Float(1.1), "fb3ff199999999999a");
        roundtrip(Cbor::Float(1.5), "f93e00");
        roundtrip(Cbor::Float(65504.0), "f97bff");
        roundtrip(Cbor::Float(100000.0), "fa47c35000");
        roundtrip(Cbor::Float(3.4028234663852886e38), "fa7f7fffff");
        roundtrip(Cbor::Float(1.0e300), "fb7e37e43c8800759c");
        roundtrip(Cbor::Float(5.960464477539063e-8), "f90001");
        roundtrip(Cbor::Float(0.00006103515625), "f90400");
        roundtrip(Cbor::Float(-4.0), "f9c400");
        roundtrip(Cbor::Float(-4.1), "fbc010666666666666");
        roundtrip(Cbor::Float(f64::INFINITY), "f97c00");
        roundtrip(Cbor::Float(f64::NAN), "f97e00");
        roundtrip(Cbor::Float(f64::NEG_INFINITY), "f9fc00");
        assert_ne!(Cbor::Float(0.0), Cbor::Float(-0.0));
    }

    #[test]
    fn rfc8949_appendix_a_other_items() {
        roundtrip(Cbor::Bool(false), "f4");
        roundtrip(Cbor::Bool(true), "f5");
        roundtrip(Cbor::Null, "f6");
        roundtrip(Cbor::Tag(1, Box::new(Cbor::Unsigned(1_363_896_240))), "c11a514b67b0");
        roundtrip(Cbor::Bytes(vec![]), "40");
        roundtrip(Cbor::Bytes(vec![1, 2, 3, 4]), "4401020304");
        roundtrip(Cbor::text(""), "60");
        roundtrip(Cbor::text("a"), "6161");
        roundtrip(Cbor::text("IETF"), "6449455446");
        roundtrip(Cbor::text("\"\\"), "62225c");
        roundtrip(Cbor::text("\u{00fc}"), "62c3bc");
        roundtrip(Cbor::text("\u{6c34}"), "63e6b0b4");
        roundtrip(Cbor::Array(vec![]), "80");
        roundtrip(Cbor::Array(vec![Cbor::Unsigned(1), Cbor::Unsigned(2), Cbor::Unsigned(3)]), "83010203");
        roundtrip(map(vec![]), "a0");
        roundtrip(
            map(vec![(Cbor::Unsigned(1), Cbor::Unsigned(2)), (Cbor::Unsigned(3), Cbor::Unsigned(4))]),
            "a201020304",
        );
        roundtrip(
            map(vec![
                (Cbor::text("a"), Cbor::Unsigned(1)),
                (Cbor::text("b"), Cbor::Array(vec![Cbor::Unsigned(2), Cbor::Unsigned(3)])),
            ]),
            "a26161016162820203",
        );
        let long: Vec<Cbor> = (1..=25).map(Cbor::Unsigned).collect();
        roundtrip(Cbor::Array(long), "98190102030405060708090a0b0c0d0e0f101112131415161718181819");
    }

    #[test]
    fn map_keys_sorted_by_encoding() {
        // RFC 8949 §4.2.1 example order: 10, 100, -1, "z", "aa", [100], [-1], false.
        let keys = vec![
            Cbor::Bool(false),
            Cbor::Array(vec![Cbor::int(-1)]),
            Cbor::text("aa"),
            Cbor::Unsigned(100),
            Cbor::Array(vec![Cbor::Unsigned(100)]),
            Cbor::int(-1),
            Cbor::text("z"),
            Cbor::Unsigned(10),
        ];
        let m: CborMap = keys.into_iter().map(|k| (k, Cbor::Null)).collect();
        let order: Vec<Vec<u8>> = m.iter().map(|(k, _)| encode(k)).collect();
        let expected: Vec<Vec<u8>> =
            ["0a", "1864", "20", "617a", "626161", "811864", "8120", "f4"].iter().map(|h| hex(h)).collect();
        assert_eq!(order, expected);
    }

    #[test]
    fn rejects_non_deterministic_input() {
        let cases = [
            ("1817", DecodeError::NotDeterministic),   // 23 with a 1-byte argument
            ("190017", DecodeError::NotDeterministic), // 23 with a 2-byte argument
            ("1a000000ff", DecodeError::NotDeterministic),
            ("fa3f800000", DecodeError::NotDeterministic), // 1.0 as binary32
            ("fb3ff0000000000000", DecodeError::NotDeterministic), // 1.0 as binary64
            ("f97e01", DecodeError::NotDeterministic),     // NaN with a payload
            ("fa7fc00000", DecodeError::NotDeterministic), // NaN as binary32
            ("a2616201616102", DecodeError::NotDeterministic), // {"b":1,"a":2}
            ("a2616101616102", DecodeError::DuplicateKey), // {"a":1,"a":2}
            ("5800", DecodeError::NotDeterministic),       // empty bytes with a 1-byte length
            ("9fff", DecodeError::IndefiniteLength),
            ("7f6161ff", DecodeError::IndefiniteLength),
            ("1c", DecodeError::Reserved),
            ("ff", DecodeError::Reserved),
            ("f7", DecodeError::UnsupportedSimpleValue), // undefined
            ("f820", DecodeError::UnsupportedSimpleValue),
            ("e0", DecodeError::UnsupportedSimpleValue),
            ("0000", DecodeError::TrailingBytes),
            ("62c328", DecodeError::InvalidUtf8),
            ("", DecodeError::UnexpectedEnd),
            ("1b0000", DecodeError::UnexpectedEnd),
            ("5bffffffffffffffff", DecodeError::UnexpectedEnd), // huge length, no allocation
            ("9bffffffffffffffff", DecodeError::UnexpectedEnd),
        ];
        for (input, expected) in cases {
            assert_eq!(decode(&hex(input)), Err(expected), "input {input}");
        }
    }

    #[test]
    fn rejects_excessive_nesting() {
        let mut deep = vec![0x81u8; MAX_DEPTH + 1];
        deep.push(0x00);
        assert_eq!(decode(&deep), Err(DecodeError::TooDeep));
        let mut ok = vec![0x81u8; MAX_DEPTH];
        ok.push(0x00);
        assert!(decode(&ok).is_ok());
    }

    #[test]
    fn f16_boundaries() {
        // Largest/smallest binary16 normals and subnormals, and values one ulp outside.
        for v in [65504.0, 6.103515625e-5, 5.960464477539063e-8, 3.0517578125e-5, 0.5, 2.0] {
            assert_eq!(encode(&Cbor::Float(v)).len(), 3, "{v} should fit binary16");
            assert_eq!(f16_to_f64(f64_to_f16_exact(v).unwrap()), v);
        }
        for v in [65505.0, 65520.0, 2.9802322387695312e-8, 1.0 + f64::EPSILON, 1.0e-10] {
            assert!(f64_to_f16_exact(v).is_none(), "{v} should not fit binary16");
        }
    }
}
