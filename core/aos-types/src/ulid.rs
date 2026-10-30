//! ULIDs (SPEC §6.1): 48-bit millisecond timestamp + 80 random bits, Crockford base32.
//!
//! The core library has no clock and no entropy source: callers pass both in.

use core::fmt;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RANDOM_BITS: u32 = 80;
const RANDOM_MASK: u128 = (1 << RANDOM_BITS) - 1;
pub const MAX_TIMESTAMP_MS: u64 = (1 << 48) - 1;

/// Ordering of ULIDs equals ordering of their text and byte forms.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ulid(u128);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UlidError {
    TimestampOutOfRange,
    RandomOutOfRange,
    /// Too many ULIDs in one millisecond: the random part would wrap.
    Overflow,
    InvalidLength,
    InvalidChar,
}

impl Ulid {
    pub fn new(timestamp_ms: u64, random: u128) -> Result<Ulid, UlidError> {
        if timestamp_ms > MAX_TIMESTAMP_MS {
            return Err(UlidError::TimestampOutOfRange);
        }
        if random > RANDOM_MASK {
            return Err(UlidError::RandomOutOfRange);
        }
        Ok(Ulid((u128::from(timestamp_ms) << RANDOM_BITS) | random))
    }

    pub const fn from_u128(v: u128) -> Ulid {
        Ulid(v)
    }

    pub const fn to_u128(self) -> u128 {
        self.0
    }

    pub const fn timestamp_ms(self) -> u64 {
        (self.0 >> RANDOM_BITS) as u64
    }

    pub const fn random(self) -> u128 {
        self.0 & RANDOM_MASK
    }

    pub const fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Ulid {
        Ulid(u128::from_be_bytes(bytes))
    }

    /// Canonical (upper-case) 26-character text form.
    pub fn encode(self) -> [u8; 26] {
        let mut out = [0u8; 26];
        for (i, c) in out.iter_mut().enumerate() {
            *c = ALPHABET[((self.0 >> (5 * (25 - i))) & 31) as usize];
        }
        out
    }

    /// Parses the text form. Lower case is accepted; I, L, O and U are not.
    pub fn parse(s: &str) -> Result<Ulid, UlidError> {
        let s = s.as_bytes();
        if s.len() != 26 {
            return Err(UlidError::InvalidLength);
        }
        let mut v: u128 = 0;
        for (i, &c) in s.iter().enumerate() {
            let d = decode_char(c).ok_or(UlidError::InvalidChar)?;
            if i == 0 && d > 7 {
                return Err(UlidError::Overflow); // 26 * 5 = 130 bits; the top two must be zero
            }
            v = (v << 5) | u128::from(d);
        }
        Ok(Ulid(v))
    }
}

fn decode_char(c: u8) -> Option<u8> {
    let c = c.to_ascii_uppercase();
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u8)
}

impl fmt::Display for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.encode();
        // The alphabet is ASCII, so this cannot fail.
        f.write_str(core::str::from_utf8(&text).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Monotonic ULID generator: within one millisecond (or if the clock moves backwards) the
/// next ULID is the previous one plus one, so ULIDs from one generator strictly increase.
#[derive(Clone, Debug, Default)]
pub struct UlidGenerator {
    last: Option<Ulid>,
}

impl UlidGenerator {
    pub const fn new() -> UlidGenerator {
        UlidGenerator { last: None }
    }

    pub fn generate(&mut self, now_ms: u64, entropy: [u8; 10]) -> Result<Ulid, UlidError> {
        let next = match self.last {
            Some(last) if now_ms <= last.timestamp_ms() => {
                let random = last.random() + 1;
                if random > RANDOM_MASK {
                    return Err(UlidError::Overflow);
                }
                Ulid::new(last.timestamp_ms(), random)?
            }
            _ => {
                let mut wide = [0u8; 16];
                wide[6..].copy_from_slice(&entropy);
                Ulid::new(now_ms, u128::from_be_bytes(wide))?
            }
        };
        self.last = Some(next);
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn known_vector() {
        // Example from the ULID specification: ulid(1469918176385) = 01ARYZ6S41TSV4RRFFQ69G5FAV.
        let u = Ulid::parse("01ARYZ6S41TSV4RRFFQ69G5FAV").unwrap();
        assert_eq!(u.timestamp_ms(), 1_469_918_176_385);
        assert_eq!(u.to_string(), "01ARYZ6S41TSV4RRFFQ69G5FAV");
        assert_eq!(Ulid::parse("01aryz6s41tsv4rrffq69g5fav"), Ok(u));
    }

    #[test]
    fn bounds_and_invalid_input() {
        let max = Ulid::new(MAX_TIMESTAMP_MS, RANDOM_MASK).unwrap();
        assert_eq!(max.to_string(), "7ZZZZZZZZZZZZZZZZZZZZZZZZZ");
        assert_eq!(Ulid::parse("80000000000000000000000000"), Err(UlidError::Overflow));
        assert_eq!(Ulid::parse("01ARZ3NDEKTSV4RRFFQ69G5FAU"), Err(UlidError::InvalidChar));
        assert_eq!(Ulid::parse("01ARZ3NDEKTSV4RRFFQ69G5FA"), Err(UlidError::InvalidLength));
        assert_eq!(Ulid::new(MAX_TIMESTAMP_MS + 1, 0), Err(UlidError::TimestampOutOfRange));
        assert_eq!(Ulid::new(0, RANDOM_MASK + 1), Err(UlidError::RandomOutOfRange));
    }

    #[test]
    fn byte_order_matches_text_order() {
        let a = Ulid::new(1, 5).unwrap();
        let b = Ulid::new(2, 0).unwrap();
        assert!(a < b);
        assert!(a.to_bytes() < b.to_bytes());
        assert!(a.to_string() < b.to_string());
        assert_eq!(Ulid::from_bytes(a.to_bytes()), a);
    }

    #[test]
    fn generator_is_monotonic() {
        let mut g = UlidGenerator::new();
        let a = g.generate(1000, [0x5a; 10]).unwrap();
        let b = g.generate(1000, [0x00; 10]).unwrap(); // same ms: +1, entropy ignored
        let c = g.generate(999, [0x00; 10]).unwrap(); // clock went backwards
        let d = g.generate(1001, [0x00; 10]).unwrap();
        assert!(a < b && b < c && c < d);
        assert_eq!(b.to_u128(), a.to_u128() + 1);
        assert_eq!(d.timestamp_ms(), 1001);
    }

    #[test]
    fn generator_overflow_is_an_error() {
        let mut g = UlidGenerator::new();
        let first = g.generate(7, [0xff; 10]).unwrap();
        assert_eq!(first.random(), RANDOM_MASK);
        assert_eq!(g.generate(7, [0; 10]), Err(UlidError::Overflow));
    }
}
