//! proptests/ct_eq.rs — property tests for constant-time equality

#[cfg(all(feature = "ct-eq", feature = "alloc"))]
mod tests {
    use proptest::prelude::*;
    use secure_gate::{dynamic_alias, fixed_alias, ConstantTimeEq};

    dynamic_alias!(TestDynamic, Vec<u8>);
    dynamic_alias!(TestDynamicStr, String);
    fixed_alias!(TestFixed, 32);

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Correctness — ct_eq must agree with regular equality on all inputs.
        /// This subsumes symmetry: if ct_eq(a,b) == (a==b) and == is symmetric,
        /// then ct_eq is symmetric. A broken impl returning a constant would fail here.
        #[test]
        fn dynamic_vec_correctness(
            a in prop::collection::vec(any::<u8>(), 0..=256),
            b in prop::collection::vec(any::<u8>(), 0..=256)
        ) {
            let da: TestDynamic = a.clone().into();
            let db: TestDynamic = b.clone().into();
            prop_assert_eq!(da.ct_eq(&db), a == b);
        }

        /// Reflexivity — ct_eq(x, x) must always return true.
        #[test]
        fn dynamic_vec_reflexivity(a in prop::collection::vec(any::<u8>(), 0..=256)) {
            let da: TestDynamic = a.into();
            prop_assert!(da.ct_eq(&da));
        }

        /// Length sensitivity — different-length inputs must always return false,
        /// regardless of content. Guards against impls that skip the length check.
        #[test]
        fn dynamic_vec_length_sensitivity(
            data in prop::collection::vec(any::<u8>(), 0..=255),
            extra_byte in any::<u8>()
        ) {
            let mut longer = data.clone();
            longer.push(extra_byte);
            let da: TestDynamic = data.into();
            let db: TestDynamic = longer.into();
            prop_assert!(!da.ct_eq(&db));
        }

        /// Correctness for Fixed<[u8; 32]> — ensures the FixedVisitor round-trip
        /// and constant-time comparison both agree with plain array equality.
        #[test]
        fn fixed_array_correctness(
            a in prop::array::uniform32(any::<u8>()),
            b in prop::array::uniform32(any::<u8>())
        ) {
            let fa: TestFixed = TestFixed::new(a);
            let fb: TestFixed = TestFixed::new(b);
            prop_assert_eq!(fa.ct_eq(&fb), a == b);
        }

        /// Reflexivity for Fixed<[u8; 32]>.
        #[test]
        fn fixed_array_reflexivity(a in prop::array::uniform32(any::<u8>())) {
            let fa: TestFixed = TestFixed::new(a);
            prop_assert!(fa.ct_eq(&fa));
        }

        /// Correctness for Dynamic<String> — exercises the String impl which
        /// delegates to the UTF-8 byte slice comparison.
        ///
        /// Uses printable ASCII to avoid JSON/string edge cases while still
        /// exercising variable-length string payloads.
        #[test]
        fn dynamic_string_correctness(
            a in "[\\x20-\\x7e]{0,256}",
            b in "[\\x20-\\x7e]{0,256}"
        ) {
            let da: TestDynamicStr = a.clone().into();
            let db: TestDynamicStr = b.clone().into();
            prop_assert_eq!(da.ct_eq(&db), a == b);
        }
    }
}
