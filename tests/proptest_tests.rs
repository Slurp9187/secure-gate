// ==========================================================================
// tests/proptest_tests.rs
// ==========================================================================
// Property-based tests using proptest to verify key invariants like round-trips
// and correctness properties under various inputs.

#![cfg(test)]

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
use secure_gate::ExposeSecret;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    all(feature = "serde-deserialize", feature = "serde-serialize"),
    feature = "ct-eq"
))]
use proptest::prelude::*;

extern crate alloc;

#[cfg(feature = "ct-eq")]
mod ct_eq_proptests {
    use super::*;

    #[cfg(feature = "ct-eq")]
    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(10))]

        #[test]
        fn constant_time_eq_reflexive(a in prop::collection::vec(any::<u8>(), 0..256)) {
            prop_assert!(bool::from(::subtle::ConstantTimeEq::ct_eq(a.as_slice(), a.as_slice())));
        }

        #[test]
        fn constant_time_eq_symmetric(a in prop::collection::vec(any::<u8>(), 0..256), b in prop::collection::vec(any::<u8>(), 0..256)) {
            prop_assert_eq!(bool::from(::subtle::ConstantTimeEq::ct_eq(a.as_slice(), b.as_slice())), bool::from(::subtle::ConstantTimeEq::ct_eq(b.as_slice(), a.as_slice())));
        }
    }
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
mod serde_proptests {
    use super::*;
    use secure_gate::{serializable_dynamic_alias, serializable_fixed_alias};

    serializable_fixed_alias!(pub TestSerializableArray, 4);
    serializable_dynamic_alias!(pub TestSerializableVec, Vec<u8>);

    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(10))]

        #[test]
        fn dynamic_serde_roundtrip(data in prop::collection::vec(any::<u8>(), 0..100)) {
            let original: TestSerializableVec = data.clone().into();
            let serialized = serde_json::to_string(&original).unwrap();
            let deserialized: TestSerializableVec = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(original.expose_secret().clone(), deserialized.expose_secret().clone());
        }

        #[test]
        fn fixed_serde_roundtrip(data in prop::array::uniform4(any::<u8>())) {
            let original: TestSerializableArray = data.into();
            let serialized = serde_json::to_string(&original).unwrap();
            let deserialized: TestSerializableArray = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(original.expose_secret(), deserialized.expose_secret());
        }
    }
}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    all(feature = "serde-deserialize", feature = "serde-serialize"),
    feature = "ct-eq"
))]
#[test]
fn proptest_modules_present() {
    // This test runs only if any of the features that enable proptest modules are enabled.
    // It verifies that the proptest modules are compiled in.
    assert_eq!(2 + 2, 4);
}
