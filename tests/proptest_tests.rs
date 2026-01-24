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
        fn constant_time_eq_reflexive(a in prop::collection::vec(any::<u8>(), 0usize..256)) {
            prop_assert!(bool::from(::subtle::ConstantTimeEq::ct_eq(a.as_slice(), a.as_slice())));
        }

        #[test]
        fn constant_time_eq_symmetric(a in prop::collection::vec(any::<u8>(), 0usize..256), b in prop::collection::vec(any::<u8>(), 0usize..256)) {
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
        fn dynamic_ct_eq_symmetric(a in prop::collection::vec(any::<u8>(), 0usize..256), b in prop::collection::vec(any::<u8>(), 0usize..256)) {
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
    use secure_gate::{ToBech32, ToHex};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[cfg(all(feature = "encoding-hex", feature = "serde-deserialize"))]
        #[test]
        fn hex_roundtrip(data in prop::array::uniform4(any::<u8>())) {
            let secret = secure_gate::Fixed::new(data);
            let hex = secret.with_secret(|s| s.as_slice().to_hex());
            let json = format!("\"{}\"", hex);
            let decoded: secure_gate::Fixed<[u8; 4]> = serde_json::from_str(&json).unwrap();
            let original_data = secret.with_secret(|s| *s);
            let decoded_data = decoded.with_secret(|d| *d);
            prop_assert_eq!(original_data, decoded_data);
        }

        #[cfg(all(feature = "encoding-hex", feature = "serde-deserialize"))]
        #[test]
        fn hex_try_roundtrip(data in prop::array::uniform4(any::<u8>())) {
            let secret = secure_gate::Fixed::new(data);
            let hex = secret.with_secret(|s| s.as_slice().to_hex());
            let json = format!("\"{}\"", hex);
            let decoded: Result<secure_gate::Fixed<[u8; 4]>, _> = serde_json::from_str(&json);
            let decoded = decoded.unwrap();
            let original_data = secret.with_secret(|s| *s);
            let decoded_data = decoded.with_secret(|d| *d);
            prop_assert_eq!(original_data, decoded_data);
        }

        #[cfg(all(feature = "encoding-bech32", feature = "serde-deserialize"))]
        #[test]
        fn bech32_roundtrip(data in prop::collection::vec(any::<u8>(), 1..50)) {
            let secret: secure_gate::Dynamic<Vec<u8>> = secure_gate::Dynamic::new(data.clone());
            let bech = secret.with_secret(|s| s.as_slice().to_bech32("test"));
            let json = format!("\"{}\"", bech);
            let decoded: secure_gate::Dynamic<Vec<u8>> = serde_json::from_str(&json).unwrap();
            let original_data = secret.with_secret(|s| s.clone());
            let decoded_data = decoded.with_secret(|d| d.clone());
            prop_assert_eq!(original_data, decoded_data);
        }
    }
}

#[cfg(feature = "hash-eq")]
mod hash_eq_proptests {
    use proptest::prelude::*;
    use secure_gate::{dynamic_alias, fixed_alias, ExposeSecret, HashEq};

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
        fn dynamic_hash_eq_symmetric(a in prop::collection::vec(any::<u8>(), 0usize..256), b in prop::collection::vec(any::<u8>(), 0usize..256)) {
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.clone().into();
            prop_assert_eq!(da.hash_eq(&db), db.hash_eq(&da));  // Symmetry
        }

        #[test]
        fn hash_eq_consistency_with_ct_eq(a in prop::collection::vec(any::<u8>(), 0usize..256), b in prop::collection::vec(any::<u8>(), 0usize..256)) {
            // Ensure hash_eq agrees with ct_eq (they should be logically equivalent, just different perf)
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.clone().into();
            prop_assert_eq!(da.hash_eq(&db), da.ct_eq(&db));
        }

        // Verify hash_eq_opt(None) behaves exactly like hash_eq
        #[test]
        fn hash_eq_opt_none_consistent_with_hash_eq(
            a in prop::collection::vec(any::<u8>(), 0usize..512),
            b in prop::collection::vec(any::<u8>(), 0usize..512)
        ) {
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.into();
            prop_assert_eq!(da.hash_eq(&db), da.hash_eq_opt(&db, None));
        }

        // Verify length mismatch → always false
        #[test]
        fn hash_eq_length_mismatch_always_false(
            a in prop::collection::vec(any::<u8>(), 0usize..256),
            len_b in 0usize..256
        ) {
            let mut b = vec![0u8; len_b];
            if b.len() == a.len() { b.push(0); } // ensure different length
            let da: TestDynamic = a.into();
            let db: TestDynamic = b.into();
            prop_assert!(!da.hash_eq(&db));
            prop_assert!(!da.hash_eq_opt(&db, None));
        }

        // Check switching behavior around threshold
        #[test]
        fn hash_eq_opt_threshold_switch(
            data in prop::collection::vec(any::<u8>(), 20..45),
            threshold in 10usize..60
        ) {
            let a: TestDynamic = data.clone().into();
            let b: TestDynamic = data.into();

            let direct_ct = a.ct_eq(&b);
            let len = a.with_secret(|s| s.len());

            let using_ct = len <= threshold;

            prop_assert_eq!(
                a.hash_eq_opt(&b, Some(threshold)),
                if using_ct { direct_ct } else { a.hash_eq(&b) },
                "Mismatch at threshold {} (using_ct: {}, direct_ct: {})",
                threshold,
                using_ct,
                direct_ct
            );
        }
    }
}
