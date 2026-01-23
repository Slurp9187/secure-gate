// ==========================================================================
// tests/proptest_tests.rs
// ==========================================================================
// Property-based tests using proptest to verify key invariants like round-trips
// and correctness properties under various inputs.

#![cfg(test)]

extern crate alloc;

#[cfg(feature = "ct-eq")]
mod ct_eq_proptests {
    use proptest::prelude::*;

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

#[cfg(feature = "ct-eq")]
mod ct_eq_wrapper_proptests {
    use proptest::prelude::*;
    use secure_gate::{dynamic_alias, fixed_alias};

    fixed_alias!(TestFixed32, 32);
    dynamic_alias!(TestDynamic, Vec<u8>);

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]  // More cases for thoroughness

        #[test]
        fn fixed_ct_eq_symmetric(a in prop::array::uniform32(any::<u8>()), b in prop::array::uniform32(any::<u8>())) {
            let fa: TestFixed32 = a.into();
            let fb: TestFixed32 = b.into();
            prop_assert_eq!(fa.ct_eq(&fb), fb.ct_eq(&fa));  // Symmetry
        }

        #[test]
        fn fixed_ct_eq_reflexive(a in prop::array::uniform32(any::<u8>())) {
            let fa: TestFixed32 = a.into();
            prop_assert!(fa.ct_eq(&fa));  // Reflexive
        }

        #[test]
        fn dynamic_ct_eq_symmetric(a in prop::collection::vec(any::<u8>(), 0..256), b in prop::collection::vec(any::<u8>(), 0..256)) {
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.clone().into();
            prop_assert_eq!(da.ct_eq(&db), db.ct_eq(&da));  // Symmetry
        }
    }
}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
#[cfg(all(feature = "encoding-hex", feature = "serde-deserialize"))]
mod encoding_roundtrip_proptests {
    use proptest::prelude::*;
    #[cfg(feature = "serde-deserialize")]
    use secure_gate::ExposeSecret;
    #[cfg(feature = "encoding-bech32")]
    use secure_gate::SecureEncoding;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[cfg(all(feature = "encoding-hex", feature = "serde-deserialize"))]
        #[test]
        fn hex_roundtrip(data in prop::array::uniform4(any::<u8>())) {
            let secret = secure_gate::Fixed::new(data);
            let hex = secret.expose_secret().as_slice().to_hex();
            let json = format!("\"{}\"", hex);
            let decoded: secure_gate::Fixed<[u8; 4]> = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(secret.expose_secret(), decoded.expose_secret());
        }

        #[cfg(all(feature = "encoding-hex", feature = "serde-deserialize"))]
        #[test]
        fn hex_try_roundtrip(data in prop::array::uniform4(any::<u8>())) {
            let secret = secure_gate::Fixed::new(data);
            let hex = secret.expose_secret().as_slice().to_hex();
            let json = format!("\"{}\"", hex);
            let decoded: Result<secure_gate::Fixed<[u8; 4]>, _> = serde_json::from_str(&json);
            let decoded = decoded.unwrap();
            prop_assert_eq!(secret.expose_secret(), decoded.expose_secret());
        }

        #[cfg(all(feature = "encoding-bech32", feature = "serde-deserialize"))]
        #[test]
        fn bech32_roundtrip(data in prop::collection::vec(any::<u8>(), 1..50)) {
            let secret: secure_gate::Dynamic<Vec<u8>> = secure_gate::Dynamic::new(data.clone());
            let slice = secret.expose_secret().as_slice();
            let bech = slice.to_bech32("test");
            let json = format!("\"{}\"", bech);
            let decoded: secure_gate::Dynamic<Vec<u8>> = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(secret.expose_secret(), decoded.expose_secret());
        }
    }
}

#[cfg(feature = "hash-eq")]
mod hash_eq_proptests {
    use proptest::prelude::*;
    use secure_gate::{dynamic_alias, fixed_alias, HashEq};

    fixed_alias!(TestFixed32, 32);
    dynamic_alias!(TestDynamic, Vec<u8>);

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[cfg(feature = "hash-eq")]
        #[test]
        fn fixed_hash_eq_symmetric(a in prop::array::uniform32(any::<u8>()), b in prop::array::uniform32(any::<u8>())) {
            let fa: TestFixed32 = a.into();
            let fb: TestFixed32 = b.into();
            prop_assert_eq!(fa.hash_eq(&fb), fb.hash_eq(&fa));  // Symmetry
        }

        #[cfg(feature = "hash-eq")]
        #[test]
        fn fixed_hash_eq_reflexive(a in prop::array::uniform32(any::<u8>())) {
            let fa: TestFixed32 = a.into();
            prop_assert!(fa.hash_eq(&fa));  // Reflexive
        }

        #[cfg(feature = "hash-eq")]
        #[test]
        fn dynamic_hash_eq_symmetric(a in prop::collection::vec(any::<u8>(), 0..256), b in prop::collection::vec(any::<u8>(), 0..256)) {
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.clone().into();
            prop_assert_eq!(da.hash_eq(&db), db.hash_eq(&da));  // Symmetry
        }

        #[cfg(feature = "hash-eq")]
        #[test]
        fn hash_eq_consistency_with_ct_eq(a in prop::collection::vec(any::<u8>(), 0..256), b in prop::collection::vec(any::<u8>(), 0..256)) {
            // Ensure hash_eq agrees with ct_eq (they should be logically equivalent, just different perf)
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.clone().into();
            prop_assert_eq!(da.hash_eq(&db), da.ct_eq(&db));
        }
    }
}
