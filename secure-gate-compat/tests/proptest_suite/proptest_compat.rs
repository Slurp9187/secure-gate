//! Property-based tests for the secrecy-compat layer (issue_104 §7).
//!
//! Generates random secrets, wraps them in compat shims, converts back-and-forth
//! between compat types and native Dynamic/Fixed, and asserts invariants:
//!
//!   1. Value identity: expose_secret() after round-trip == original value
//!   2. Debug invariant: format!("{:?}") never contains the secret
//!   3. Clone independence: modifying a clone does not affect the original
//!   4. ct_eq agreement (when feature = "ct-eq"): ct_eq must agree with ==

#[cfg(all(feature = "secrecy-compat", feature = "alloc"))]
#[allow(unused_imports)]
mod tests {
    use proptest::prelude::*;
    use secure_gate::{Dynamic, Fixed};
    use secure_gate_compat::compat::v08::Secret as V08Secret;
    use secure_gate_compat::compat::v10::{
        SecretBox as V10SecretBox, SecretString as V10SecretString,
    };
    use secure_gate_compat::compat::{ExposeSecret, ExposeSecretMut};

    // ── v08::Secret<String> round-trips ──────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Value identity: V08Secret<String> → Dynamic<String> → V08Secret<String>
        #[test]
        fn v08_string_round_trip(s in "[\\x20-\\x7e]{0,256}") {
            let v08: V08Secret<String> = V08Secret::new(s.clone());
            let native: Dynamic<String> = v08.into();
            let v08_back: V08Secret<String> = native.into();
            prop_assert_eq!(v08_back.expose_secret(), &s);
        }

        /// Value identity: V08Secret<Vec<u8>> → Dynamic<Vec<u8>> → V08Secret<Vec<u8>>
        #[test]
        fn v08_vec_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
            let v08: V08Secret<Vec<u8>> = V08Secret::new(bytes.clone());
            let native: Dynamic<Vec<u8>> = v08.into();
            let v08_back: V08Secret<Vec<u8>> = native.into();
            prop_assert_eq!(v08_back.expose_secret(), &bytes);
        }

        /// Value identity: V08Secret<[u8; 32]> → Fixed<[u8; 32]> → V08Secret<[u8; 32]>
        #[test]
        fn v08_array32_round_trip(arr in prop::array::uniform32(any::<u8>())) {
            let v08: V08Secret<[u8; 32]> = V08Secret::new(arr);
            let fixed: Fixed<[u8; 32]> = v08.into();
            let v08_back: V08Secret<[u8; 32]> = fixed.into();
            prop_assert_eq!(*v08_back.expose_secret(), arr);
        }

        /// Debug invariant: V08Secret<String> debug output never contains the payload.
        #[test]
        fn v08_string_debug_never_leaks(s in "[a-zA-Z0-9]{4,64}") {
            let v08: V08Secret<String> = V08Secret::new(s.clone());
            let dbg = format!("{:?}", v08);
            // The payload must not appear anywhere in the debug output.
            prop_assert!(!dbg.contains(s.as_str()),
                "Debug output leaked secret: {}", s);
        }

        /// Clone independence: modifying clone via round-trip does not affect original.
        #[test]
        fn v08_string_clone_independence(s in "[\\x20-\\x7e]{1,128}") {
            let original: V08Secret<String> = V08Secret::new(s.clone());
            let clone_a: V08Secret<String> = original.clone();

            // Mutate clone_a via Dynamic round-trip
            let mut native: Dynamic<String> = clone_a.into();
            native.expose_secret_mut().push_str("_mutated");
            let clone_a_mut: V08Secret<String> = native.into();

            // Original is unchanged
            prop_assert_eq!(original.expose_secret(), &s,
                "Original was mutated when clone was modified");
            prop_assert!(clone_a_mut.expose_secret().ends_with("_mutated"));
        }
    }

    // ── v10::SecretBox<String> round-trips ───────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Value identity: V10SecretBox<String> → Dynamic<String> → V10SecretBox<String>
        #[test]
        fn v10_string_round_trip(s in "[\\x20-\\x7e]{0,256}") {
            let v10: V10SecretBox<String> = V10SecretBox::init_with(|| s.clone());
            let native: Dynamic<String> = v10.into();
            let v10_back: V10SecretBox<String> = native.into();
            prop_assert_eq!(v10_back.expose_secret(), &s);
        }

        /// Value identity: V10SecretBox<Vec<u8>> → Dynamic<Vec<u8>> → V10SecretBox<Vec<u8>>
        #[test]
        fn v10_vec_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
            let v10: V10SecretBox<Vec<u8>> = V10SecretBox::new(Box::new(bytes.clone()));
            let native: Dynamic<Vec<u8>> = v10.into();
            let v10_back: V10SecretBox<Vec<u8>> = native.into();
            prop_assert_eq!(v10_back.expose_secret(), &bytes);
        }

        /// SecretString round-trip.
        #[test]
        fn v10_secret_string_round_trip(s in "[\\x20-\\x7e]{0,128}") {
            let ss: V10SecretString = s.clone().into();
            let native: Dynamic<String> = ss.into();
            let ss_back: V10SecretString = native.into();
            prop_assert_eq!(ss_back.expose_secret(), s.as_str());
        }

        /// Debug invariant: V10SecretBox<String> never leaks.
        #[test]
        fn v10_string_debug_never_leaks(s in "[a-zA-Z0-9]{4,64}") {
            let v10: V10SecretBox<String> = V10SecretBox::init_with(|| s.clone());
            let dbg = format!("{:?}", v10);
            prop_assert!(!dbg.contains(s.as_str()),
                "V10SecretBox Debug leaked secret: {}", s);
        }

        /// Mutable access preserves value identity.
        #[test]
        fn v10_mutable_access_identity(
            s in "[\\x20-\\x7e]{1,64}",
            suffix in "[\\x20-\\x7e]{1,32}"
        ) {
            let mut sb: V10SecretBox<String> = V10SecretBox::init_with(|| s.clone());
            sb.expose_secret_mut().push_str(&suffix);
            let expected = format!("{}{}", s, suffix);
            prop_assert_eq!(sb.expose_secret(), &expected);
        }
    }

    // ── Cross-version round-trips ─────────────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Full chain: v08 → Dynamic → v10 → Dynamic → v08 (string).
        #[test]
        fn full_chain_string(s in "[\\x20-\\x7e]{0,128}") {
            let v08: V08Secret<String> = V08Secret::new(s.clone());
            let d1: Dynamic<String> = v08.into();
            let v10: V10SecretBox<String> = d1.into();
            let d2: Dynamic<String> = v10.into();
            let v08_back: V08Secret<String> = d2.into();
            prop_assert_eq!(v08_back.expose_secret(), &s);
        }

        /// Full chain: v08 → Dynamic → v10 → Dynamic → v08 (Vec<u8>).
        #[test]
        fn full_chain_vec(bytes in prop::collection::vec(any::<u8>(), 0..=256)) {
            let v08: V08Secret<Vec<u8>> = V08Secret::new(bytes.clone());
            let d1: Dynamic<Vec<u8>> = v08.into();
            let v10: V10SecretBox<Vec<u8>> = d1.into();
            let d2: Dynamic<Vec<u8>> = v10.into();
            let v08_back: V08Secret<Vec<u8>> = d2.into();
            prop_assert_eq!(v08_back.expose_secret(), &bytes);
        }
    }

    // ── ct_eq agreement after round-trips ────────────────────────────────────

    #[cfg(feature = "ct-eq")]
    mod ct_eq_props {
        use super::*;
        use secure_gate::ConstantTimeEq;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// ct_eq must agree with == after v08 round-trip.
            #[test]
            fn ct_eq_agrees_after_v08_round_trip(
                a in prop::collection::vec(any::<u8>(), 0..=256),
                b in prop::collection::vec(any::<u8>(), 0..=256)
            ) {
                let v08_a: V08Secret<Vec<u8>> = V08Secret::new(a.clone());
                let da: Dynamic<Vec<u8>> = v08_a.into();

                let v08_b: V08Secret<Vec<u8>> = V08Secret::new(b.clone());
                let db: Dynamic<Vec<u8>> = v08_b.into();

                prop_assert_eq!(da.ct_eq(&db), a == b,
                    "ct_eq disagreed with == after v08 round-trip");
            }

            /// ct_eq reflexivity after round-trip.
            #[test]
            fn ct_eq_reflexive_after_round_trip(
                bytes in prop::collection::vec(any::<u8>(), 0..=256)
            ) {
                let v10: V10SecretBox<Vec<u8>> = V10SecretBox::new(Box::new(bytes.clone()));
                let da: Dynamic<Vec<u8>> = v10.into();

                let v10b: V10SecretBox<Vec<u8>> = V10SecretBox::new(Box::new(bytes));
                let db: Dynamic<Vec<u8>> = v10b.into();

                prop_assert!(da.ct_eq(&db), "ct_eq must be reflexive after v10 round-trip");
            }

            /// ct_eq string correctness after v10 round-trip.
            #[test]
            fn ct_eq_string_after_v10_round_trip(
                a in "[\\x20-\\x7e]{0,128}",
                b in "[\\x20-\\x7e]{0,128}"
            ) {
                let v10_a: V10SecretBox<String> = V10SecretBox::init_with(|| a.clone());
                let da: Dynamic<String> = v10_a.into();

                let v10_b: V10SecretBox<String> = V10SecretBox::init_with(|| b.clone());
                let db: Dynamic<String> = v10_b.into();

                prop_assert_eq!(da.ct_eq(&db), a == b,
                    "ct_eq disagreed with == for strings after v10 round-trip");
            }
        }
    }
}
