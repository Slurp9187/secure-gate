//! proptests/ct_eq.rs — property tests for ct_eq

#[cfg(all(feature = "ct-eq", feature = "alloc"))]
mod tests {
    use proptest::prelude::*;
    use secure_gate::{dynamic_alias, ConstantTimeEq};

    dynamic_alias!(TestDynamic, Vec<u8>);

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn ct_eq_symmetric(
            a in prop_oneof![
                Just(vec![]),
                prop::collection::vec(any::<u8>(), 1..=1),
                Just(vec![0xFFu8; 255]),
                prop::collection::vec(any::<u8>(), 0usize..256),
            ],
            b in prop_oneof![
                Just(vec![]),
                prop::collection::vec(any::<u8>(), 1..=1),
                Just(vec![0x00u8; 255]),
                prop::collection::vec(any::<u8>(), 0usize..256),
            ]
        ) {
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.clone().into();
            prop_assert_eq!(da.ct_eq(&db), db.ct_eq(&da));
        }
    }
}
