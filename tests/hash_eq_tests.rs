// ==========================================================================
// tests/hash_eq_tests.rs
// ==========================================================================
// Tests for hash-based equality (Blake3) for large/variable secrets

// #[cfg(all(test, feature = "hash-eq", feature = "ct-eq"))]
#[cfg(all(test, feature = "hash-eq"))]
mod hash_eq_tests {
    use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut, Fixed, HashEq};

    // -------------------------------------------------------------------------
    // Basic correctness – same type, same length
    // -------------------------------------------------------------------------

    #[test]
    fn basic_equal_fixed() {
        let a = Fixed::new([17u8; 23]);
        let b = Fixed::new([17u8; 23]);
        assert!(a.hash_eq(&b));
        assert!(a.hash_eq_opt(&b, None));
        assert!(a.hash_eq_opt(&b, Some(10)));
        assert!(a.hash_eq_opt(&b, Some(50)));
    }

    #[test]
    fn basic_unequal_fixed_same_length() {
        let a = Fixed::new([17u8; 23]);
        let b = Fixed::new([18u8; 23]);
        assert!(!a.hash_eq(&b));
        assert!(!a.hash_eq_opt(&b, None));
    }

    #[test]
    fn basic_equal_dynamic_vec() {
        let a: Dynamic<Vec<u8>> = vec![99u8; 0].into(); // empty
        let b: Dynamic<Vec<u8>> = vec![99u8; 0].into();
        assert!(a.hash_eq(&b));
        assert!(a.hash_eq_opt(&b, None));
    }

    #[test]
    fn basic_equal_dynamic_string() {
        let a: Dynamic<String> = "café".into();
        let b: Dynamic<String> = "café".into();
        assert!(a.hash_eq(&b));
        assert!(a.hash_eq_opt(&b, None));
    }

    // -------------------------------------------------------------------------
    // Length mismatch handling (critical for both methods)
    // -------------------------------------------------------------------------

    #[test]
    fn length_mismatch_hash_eq() {
        let a: Dynamic<Vec<u8>> = vec![0u8; 50].into();
        let b: Dynamic<Vec<u8>> = vec![0u8; 51].into();
        assert!(!a.hash_eq(&b));
    }

    #[test]
    fn length_mismatch_hash_eq_opt() {
        let a: Dynamic<Vec<u8>> = vec![0u8; 50].into();
        let b: Dynamic<Vec<u8>> = vec![0u8; 51].into();
        assert!(!a.hash_eq_opt(&b, None));
        assert!(!a.hash_eq_opt(&b, Some(0)));
        assert!(!a.hash_eq_opt(&b, Some(1000)));
    }

    #[test]
    fn length_mismatch_fixed() {
        let _a = Fixed::new([0u8; 32]);
        let _b = Fixed::new([0u8; 16]); // different array size → different T
                                        // This should not even compile in real usage if types differ
                                        // But if you ever allow comparing different Fixed sizes, this would fail
    }

    // -------------------------------------------------------------------------
    // hash_eq_opt switching behavior
    // -------------------------------------------------------------------------

    #[test]
    fn hash_eq_opt_small_input_default_threshold() {
        let a = Fixed::new([77u8; 20]);
        let b = Fixed::new([77u8; 20]);
        let c = Fixed::new([78u8; 20]);

        // Should use ct_eq path (20 ≤ 32)
        assert!(a.hash_eq_opt(&b, None));
        assert!(!a.hash_eq_opt(&c, None));
    }

    #[test]
    fn hash_eq_opt_large_input_default_threshold() {
        let a: Dynamic<Vec<u8>> = vec![55u8; 1500].into();
        let b: Dynamic<Vec<u8>> = vec![55u8; 1500].into();
        let c: Dynamic<Vec<u8>> = vec![56u8; 1500].into();

        // Should use hash_eq path (1500 > 32)
        assert!(a.hash_eq_opt(&b, None));
        assert!(!a.hash_eq_opt(&c, None));
    }

    #[test]
    fn hash_eq_opt_exact_threshold_boundary() {
        let data = vec![0xA5u8; 32];
        let a: Dynamic<Vec<u8>> = data.clone().into();
        let b: Dynamic<Vec<u8>> = data.into();

        assert!(a.hash_eq_opt(&b, Some(31))); // > 31 → hash_eq
        assert!(a.hash_eq_opt(&b, Some(32))); // ≤ 32 → ct_eq
        assert!(a.hash_eq_opt(&b, Some(33))); // ≤ 33 → ct_eq
    }

    #[test]
    fn hash_eq_opt_force_ct_eq_on_large() {
        let a: Dynamic<Vec<u8>> = vec![0u8; 8192].into();
        let b: Dynamic<Vec<u8>> = vec![0u8; 8192].into();

        // Force ct_eq even though large
        assert!(a.hash_eq_opt(&b, Some(16384)));
    }

    #[test]
    fn hash_eq_opt_force_hash_on_small() {
        let a = Fixed::new([0xFFu8; 8]);
        let b = Fixed::new([0xFFu8; 8]);

        // Force hash_eq even though small
        assert!(a.hash_eq_opt(&b, Some(0)));
    }

    // -------------------------------------------------------------------------
    // Empty & very small cases
    // -------------------------------------------------------------------------

    #[test]
    fn empty_dynamic_equal() {
        let a: Dynamic<Vec<u8>> = vec![].into();
        let b: Dynamic<Vec<u8>> = vec![].into();
        assert!(a.hash_eq(&b));
        assert!(a.hash_eq_opt(&b, None));
        assert!(a.hash_eq_opt(&b, Some(0)));
    }

    #[test]
    fn empty_vs_non_empty() {
        let empty: Dynamic<Vec<u8>> = vec![].into();
        let one_byte: Dynamic<Vec<u8>> = vec![0].into();
        assert!(!empty.hash_eq(&one_byte));
        assert!(!empty.hash_eq_opt(&one_byte, None));
    }

    // -------------------------------------------------------------------------
    // Probabilistic collision safety (smoke test)
    // -------------------------------------------------------------------------

    #[test]
    // This is a probabilistic smoke test only.
    // BLAKE3 collision probability is ~2⁻¹²⁸ — extremely unlikely to hit in 5000 samples.
    fn no_false_positive_many_random_pairs() {
        use rand::{rngs::OsRng, TryRngCore};

        let mut rng = OsRng;
        const PAIRS: usize = 5000;
        const LEN: usize = 128;

        for _ in 0..PAIRS {
            let mut left = vec![0u8; LEN];
            let mut right = vec![0u8; LEN];

            rng.try_fill_bytes(&mut left).expect("RNG failure");
            right.clone_from(&left);

            // make them different
            let pos = (rng.try_next_u64().expect("RNG failure") as usize) % LEN;
            right[pos] = right[pos].wrapping_add(1);

            let a: Dynamic<Vec<u8>> = left.into();
            let b: Dynamic<Vec<u8>> = right.into();

            assert!(!a.hash_eq(&b), "False positive detected");
            assert!(!a.hash_eq_opt(&b, None));
        }
    }

    // -------------------------------------------------------------------------
    // Consistency between hash_eq and hash_eq_opt(None)
    // -------------------------------------------------------------------------

    #[test]
    fn hash_eq_and_opt_none_are_consistent() {
        let cases = vec![
            vec![],             // empty
            vec![0u8; 1],       // tiny
            vec![0u8; 31],      // under default threshold
            vec![0u8; 32],      // at threshold
            vec![0u8; 100],     // over
            vec![0xAAu8; 4096], // large
        ];

        for data in cases {
            let a: Dynamic<Vec<u8>> = data.clone().into();
            let mut b: Dynamic<Vec<u8>> = data.into();

            // equal
            assert_eq!(a.hash_eq(&b), a.hash_eq_opt(&b, None));

            // mutate last byte → unequal
            if !b.expose_secret().is_empty() {
                let last = b.expose_secret().len() - 1;
                let current = b.expose_secret()[last];
                b.expose_secret_mut()[last] = current.wrapping_add(1);
                assert_eq!(a.hash_eq(&b), a.hash_eq_opt(&b, None));
                assert!(!a.hash_eq(&b));
            }
        }
    }

    #[test]
    fn basic_equal_fixed_tiny() {
        let a = Fixed::new([0u8; 1]);
        let b = Fixed::new([0u8; 1]);
        let c = Fixed::new([1u8; 1]);
        assert!(a.hash_eq(&b));
        assert!(a.hash_eq_opt(&b, None)); // should use ct_eq
        assert!(!a.hash_eq_opt(&c, None));
    }
}
