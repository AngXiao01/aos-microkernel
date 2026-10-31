//! SHA-256 content hashes (SPEC §6.4, §7.1).

use core::fmt;

use sha2::{Digest, Sha256};

use crate::cbor::{self, Cbor};

const PREFIX: &str = "sha256:";

/// A SHA-256 digest. Text form: `sha256:<64 lowercase hex digits>`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash256(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseHashError;

impl Hash256 {
    pub fn digest(data: &[u8]) -> Hash256 {
        Hash256(Sha256::digest(data).into())
    }

    /// Hash of the deterministic encoding of `value`.
    pub fn of_cbor(value: &Cbor) -> Hash256 {
        Hash256::digest(&cbor::encode(value))
    }

    pub fn parse(s: &str) -> Result<Hash256, ParseHashError> {
        let hex = s.strip_prefix(PREFIX).ok_or(ParseHashError)?.as_bytes();
        if hex.len() != 64 {
            return Err(ParseHashError);
        }
        let mut out = [0u8; 32];
        for (byte, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
            *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Hash256(out))
    }
}

fn nibble(c: u8) -> Result<u8, ParseHashError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(ParseHashError),
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PREFIX)?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            Hash256::digest(b"abc").to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            Hash256::digest(b"").to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn text_form_roundtrip_and_strictness() {
        let h = Hash256::digest(b"aos");
        assert_eq!(Hash256::parse(&h.to_string()), Ok(h));
        let upper = h.to_string().to_uppercase().replace("SHA256:", "sha256:");
        assert_eq!(Hash256::parse(&upper), Err(ParseHashError));
        assert_eq!(Hash256::parse("sha256:00"), Err(ParseHashError));
        assert_eq!(Hash256::parse(&h.to_string()[7..]), Err(ParseHashError));
    }
}
