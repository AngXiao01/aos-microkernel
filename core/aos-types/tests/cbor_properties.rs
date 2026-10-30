//! Property tests: deterministic CBOR has exactly one accepted encoding per value.

use aos_types::cbor::{Cbor, CborMap, decode, encode};
use aos_types::{Finite, ObjectRef, Ulid, Value, from_bytes, to_bytes};
use proptest::prelude::*;

fn arb_cbor() -> impl Strategy<Value = Cbor> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Cbor::Unsigned),
        any::<u64>().prop_map(Cbor::Negative),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Cbor::Bytes),
        ".{0,20}".prop_map(Cbor::Text),
        any::<bool>().prop_map(Cbor::Bool),
        Just(Cbor::Null),
        any::<f64>().prop_map(Cbor::Float),
        // Values that hit the binary16/binary32 paths.
        any::<i16>().prop_map(|n| Cbor::Float(f64::from(n) / 8.0)),
        any::<f32>().prop_map(|f| Cbor::Float(f64::from(f))),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(Cbor::Array),
            proptest::collection::vec((inner.clone(), inner.clone()), 0..8)
                .prop_map(|entries| Cbor::Map(entries.into_iter().collect::<CborMap>())),
            (any::<u64>(), inner).prop_map(|(t, v)| Cbor::Tag(t, Box::new(v))),
        ]
    })
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::Int),
        any::<f64>().prop_filter_map("finite", |f| Finite::new(f).map(Value::Float)),
        ".{0,20}".prop_map(Value::Text),
        proptest::collection::vec(any::<u8>(), 0..20).prop_map(Value::Bytes),
        (any::<u128>(), proptest::option::of(any::<u64>()))
            .prop_map(|(id, v)| Value::Ref(ObjectRef { id: Ulid::from_u128(id), version: v })),
        any::<[u8; 32]>().prop_map(|h| Value::Blob(aos_types::Hash256(h))),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::List),
            proptest::collection::btree_map("[a-z_]{0,8}", inner, 0..8).prop_map(Value::Map),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn encode_then_decode_is_identity(value in arb_cbor()) {
        let bytes = encode(&value);
        prop_assert_eq!(decode(&bytes), Ok(value));
    }

    /// Whatever bytes the strict decoder accepts, re-encoding reproduces them exactly.
    #[test]
    fn accepted_bytes_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(value) = decode(&bytes) {
            prop_assert_eq!(encode(&value), bytes);
        }
    }

    /// Mutating one byte of a valid encoding either fails or yields a different value.
    #[test]
    fn single_byte_mutation_never_aliases(value in arb_cbor(), index in any::<prop::sample::Index>(), flip in 1u8..=255) {
        let mut bytes = encode(&value);
        let i = index.index(bytes.len());
        bytes[i] ^= flip;
        if let Ok(other) = decode(&bytes) {
            prop_assert_ne!(other, value);
        }
    }

    #[test]
    fn value_roundtrip(value in arb_value()) {
        prop_assert_eq!(from_bytes::<Value>(&to_bytes(&value)), Ok(value));
    }
}
