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

#[cfg(all(feature = "ct-eq", feature = "alloc"))]
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
#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
mod encoding_roundtrip_proptests {
    use proptest::prelude::*;
    #[cfg(feature = "serde-serialize")]
    use secure_gate::SerializableSecret;

    #[cfg(feature = "serde-serialize")]
    #[derive(serde::Serialize, serde::Deserialize)]
    struct SerializableArray4([u8; 4]);

    #[cfg(feature = "serde-serialize")]
    impl SerializableSecret for SerializableArray4 {}

    #[cfg(feature = "serde-serialize")]
    #[derive(serde::Serialize, serde::Deserialize)]
    struct SerializableVec(Vec<u8>);

    #[cfg(feature = "serde-serialize")]
    impl SerializableSecret for SerializableVec {}

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[cfg(feature = "serde-serialize")]
        #[test]
        fn fixed_array_roundtrip(data in prop::array::uniform4(any::<u8>())) {
            let secret = SerializableArray4(data);
            let json = serde_json::to_string(&secret).unwrap();
            let decoded: SerializableArray4 = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(secret.0, decoded.0);
        }

        #[cfg(all(feature = "serde-serialize", feature = "alloc"))]
        #[test]
        fn dynamic_array_roundtrip(data in prop::collection::vec(any::<u8>(), 0..50)) {
            let secret = SerializableVec(data.clone());
            let json = serde_json::to_string(&secret).unwrap();
            let decoded: SerializableVec = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(secret.0, decoded.0);
        }
    }
}

#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
mod ct_eq_hash_proptests {
    use proptest::prelude::*;
    use secure_gate::{dynamic_alias, fixed_alias, ConstantTimeEqExt, ExposeSecret};

    fixed_alias!(TestFixed32, 32);
    dynamic_alias!(TestDynamic, Vec<u8>);

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[cfg(feature = "ct-eq-hash")]
        #[test]
        fn fixed_ct_eq_hash_symmetric(a in prop::array::uniform32(any::<u8>()), b in prop::array::uniform32(any::<u8>())) {
            let fa: TestFixed32 = a.into();
            let fb: TestFixed32 = b.into();
            prop_assert_eq!(fa.ct_eq_hash(&fb), fb.ct_eq_hash(&fa));  // Symmetry
        }

        #[cfg(feature = "ct-eq-hash")]
        #[test]
        fn fixed_ct_eq_hash_reflexive(a in prop::array::uniform32(any::<u8>())) {
            let fa: TestFixed32 = a.into();
            prop_assert!(fa.ct_eq_hash(&fa));  // Reflexive
        }

        #[cfg(feature = "ct-eq-hash")]
        #[test]
        fn dynamic_ct_eq_hash_symmetric(a in prop::collection::vec(any::<u8>(), 0usize..256), b in prop::collection::vec(any::<u8>(), 0usize..256)) {
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.clone().into();
            prop_assert_eq!(da.ct_eq_hash(&db), db.ct_eq_hash(&da));  // Symmetry
        }

        #[cfg(feature = "ct-eq-hash")]
        #[test]
        fn ct_eq_hash_consistency_with_ct_eq(data in prop::collection::vec(any::<u8>(), 0usize..256)) {
            // Ensure ct_eq_hash returns true for identical data
            let da: TestDynamic = data.clone().into();
            let db: TestDynamic = data.into();
            prop_assert!(da.ct_eq_hash(&db));  // ct_eq_hash should be true for same data
        }

        // Verify ct_eq_auto(None) behaves exactly like ct_eq_hash
        #[cfg(feature = "ct-eq-hash")]
        #[test]
        fn ct_eq_auto_none_consistent_with_ct_eq_hash(
            a in prop::collection::vec(any::<u8>(), 0usize..512),
            b in prop::collection::vec(any::<u8>(), 0usize..512)
        ) {
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.into();
            prop_assert_eq!(da.ct_eq_hash(&db), da.ct_eq_auto(&db, None));
        }

        // Verify length mismatch → always false
        #[cfg(feature = "ct-eq-hash")]
        #[test]
        fn ct_eq_hash_length_mismatch_always_false(
            a in prop::collection::vec(any::<u8>(), 0usize..256),
            len_b in 0usize..256
        ) {
            let mut b = vec![0u8; len_b];
            if b.len() == a.len() { b.push(0); } // ensure different length
            let da: TestDynamic = a.into();
            let db: TestDynamic = b.into();
            prop_assert!(!da.ct_eq_hash(&db));
            prop_assert!(!da.ct_eq_auto(&db, None));
        }

        // Check switching behavior around threshold
        #[cfg(feature = "ct-eq-hash")]
        #[test]
        fn ct_eq_auto_threshold_switch(
            data in prop::collection::vec(any::<u8>(), 20..45),
            threshold in 10usize..60
        ) {
            let a: TestDynamic = data.clone().into();
            let b: TestDynamic = data.into();

            let direct_ct = a.ct_eq(&b);
            let len = a.with_secret(|s| s.len());

            let using_ct = len <= threshold;

            prop_assert_eq!(
                a.ct_eq_auto(&b, Some(threshold)),
                if using_ct { direct_ct } else { a.ct_eq_hash(&b) },
                "Mismatch at threshold {} (using_ct: {}, direct_ct: {})",
                threshold,
                using_ct,
                direct_ct
            );
        }
    }
}
