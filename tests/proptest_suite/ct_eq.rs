//! proptests/ct_eq.rs — property tests for ct_eq and ct_eq_auto

#[cfg(all(feature = "ct-eq", feature = "alloc"))]
mod tests {
    use proptest::prelude::*;
    use secure_gate::{dynamic_alias, ConstantTimeEq};

    dynamic_alias!(TestDynamic, Vec<u8>);

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[test]
        fn ct_eq_symmetric(a in prop::collection::vec(any::<u8>(), 0usize..256), b in prop::collection::vec(any::<u8>(), 0usize..256)) {
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.clone().into();
            prop_assert_eq!(da.ct_eq(&db), db.ct_eq(&da));
        }
    }
}

#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
mod auto_threshold_tests {
    use proptest::prelude::*;
    use secure_gate::{dynamic_alias, ConstantTimeEq, ConstantTimeEqExt};

    dynamic_alias!(TestDynamic2, Vec<u8>);

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[test]
        fn ct_eq_auto_threshold_switch(
            data_a in prop::collection::vec(any::<u8>(), 20..45),
            data_b in prop::collection::vec(any::<u8>(), 20..45),
            threshold in 10usize..60
        ) {
            let a: TestDynamic2 = data_a.clone().into();
            let b: TestDynamic2 = data_b.clone().into();
            // Only compare when equal length (ct_eq_auto returns false immediately on len mismatch)
            if data_a.len() == data_b.len() {
                let direct_ct = a.ct_eq(&b);
                let len = data_a.len();
                let expected = if len <= threshold { direct_ct } else { a.ct_eq_hash(&b) };
                prop_assert_eq!(a.ct_eq_auto(&b, Some(threshold)), expected);
            }
        }
    }
}
