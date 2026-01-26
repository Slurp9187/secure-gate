// ==========================================================================
// tests/ct_eq_hash_tests.rs
// ==========================================================================
// Tests for hash-based equality (Blake3) for large/variable secrets

#[cfg(all(test, feature = "ct-eq-hash"))]
mod ct_eq_hash_tests {
    use secure_gate::{ConstantTimeEqExt, Fixed};
    #[cfg(feature = "alloc")]
    use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};

    // -------------------------------------------------------------------------
    // Basic correctness – same type, same length
    // -------------------------------------------------------------------------

    #[test]
    fn basic_equal_fixed() {
        let a = Fixed::new([17u8; 23]);
        let b = Fixed::new([17u8; 23]);
        assert!(a.ct_eq_hash(&b));
        assert!(a.ct_eq_auto(&b, None));
        assert!(a.ct_eq_auto(&b, Some(10)));
        assert!(a.ct_eq_auto(&b, Some(50)));
    }

    #[test]
    fn basic_unequal_fixed_same_length() {
        let a = Fixed::new([17u8; 23]);
        let b = Fixed::new([18u8; 23]);
        assert!(!a.ct_eq_hash(&b));
        assert!(!a.ct_eq_auto(&b, None));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn basic_equal_dynamic_vec() {
        let a: Dynamic<Vec<u8>> = vec![99u8; 0].into(); // empty
        let b: Dynamic<Vec<u8>> = vec![99u8; 0].into();
        assert!(a.ct_eq_hash(&b));
        assert!(a.ct_eq_auto(&b, None));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn basic_equal_dynamic_string() {
        let a: Dynamic<String> = "café".into();
        let b: Dynamic<String> = "café".into();
        assert!(a.ct_eq_hash(&b));
        assert!(a.ct_eq_auto(&b, None));
    }

    // -------------------------------------------------------------------------
    // Length mismatch handling (critical for both methods)
    // -------------------------------------------------------------------------

    #[test]
    #[cfg(feature = "alloc")]
    fn length_mismatch_ct_eq_hash() {
        let a: Dynamic<Vec<u8>> = vec![0u8; 50].into();
        let b: Dynamic<Vec<u8>> = vec![0u8; 51].into();
        assert!(!a.ct_eq_hash(&b));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn length_mismatch_ct_eq_auto() {
        let a: Dynamic<Vec<u8>> = vec![0u8; 50].into();
        let b: Dynamic<Vec<u8>> = vec![0u8; 51].into();
        assert!(!a.ct_eq_auto(&b, None));
        assert!(!a.ct_eq_auto(&b, Some(0)));
        assert!(!a.ct_eq_auto(&b, Some(1000)));
    }

    #[test]
    fn length_mismatch_fixed() {
        let _a = Fixed::new([0u8; 32]);
        let _b = Fixed::new([0u8; 16]); // different array size → different T
                                        // This should not even compile in real usage if types differ
                                        // But if you ever allow comparing different Fixed sizes, this would fail
    }

    // -------------------------------------------------------------------------
    // ct_eq_auto switching behavior
    // -------------------------------------------------------------------------

    #[test]
    fn ct_eq_auto_small_input_default_threshold() {
        let a = Fixed::new([77u8; 20]);
        let b = Fixed::new([77u8; 20]);
        let c = Fixed::new([78u8; 20]);

        // Should use ct_eq path (20 ≤ 32)
        assert!(a.ct_eq_auto(&b, None));
        assert!(!a.ct_eq_auto(&c, None));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn ct_eq_auto_large_input_default_threshold() {
        let a: Dynamic<Vec<u8>> = vec![55u8; 1500].into();
        let b: Dynamic<Vec<u8>> = vec![55u8; 1500].into();
        let c: Dynamic<Vec<u8>> = vec![56u8; 1500].into();

        // Should use ct_eq_hash path (1500 > 32)
        assert!(a.ct_eq_auto(&b, None));
        assert!(!a.ct_eq_auto(&c, None));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn ct_eq_auto_exact_threshold_boundary() {
        let data = vec![0xA5u8; 32];
        let a: Dynamic<Vec<u8>> = data.clone().into();
        let b: Dynamic<Vec<u8>> = data.into();

        assert!(a.ct_eq_auto(&b, Some(31))); // > 31 → ct_eq_hash
        assert!(a.ct_eq_auto(&b, Some(32))); // ≤ 32 → ct_eq
        assert!(a.ct_eq_auto(&b, Some(33))); // ≤ 33 → ct_eq
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn ct_eq_auto_force_ct_eq_on_large() {
        let a: Dynamic<Vec<u8>> = vec![0u8; 8192].into();
        let b: Dynamic<Vec<u8>> = vec![0u8; 8192].into();

        // Force ct_eq even though large
        assert!(a.ct_eq_auto(&b, Some(16384)));
    }

    #[test]
    fn ct_eq_auto_force_hash_on_small() {
        let a = Fixed::new([0xFFu8; 8]);
        let b = Fixed::new([0xFFu8; 8]);

        // Force ct_eq_hash even though small
        assert!(a.ct_eq_auto(&b, Some(0)));
    }

    // -------------------------------------------------------------------------
    // Empty & very small cases
    // -------------------------------------------------------------------------

    #[cfg(feature = "alloc")]
    #[test]
    fn empty_dynamic_equal() {
        let a: Dynamic<Vec<u8>> = vec![].into();
        let b: Dynamic<Vec<u8>> = vec![].into();
        assert!(a.ct_eq_hash(&b));
        assert!(a.ct_eq_auto(&b, None));
        assert!(a.ct_eq_auto(&b, Some(0)));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn empty_vs_non_empty() {
        let empty: Dynamic<Vec<u8>> = vec![].into();
        let one_byte: Dynamic<Vec<u8>> = vec![0].into();
        assert!(!empty.ct_eq_hash(&one_byte));
        assert!(!empty.ct_eq_auto(&one_byte, None));
    }

    // -------------------------------------------------------------------------
    // Probabilistic collision safety (smoke test)
    // -------------------------------------------------------------------------

    #[cfg(feature = "rand")]
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

            #[cfg(feature = "alloc")]
            let a: Dynamic<Vec<u8>> = left.into();
            #[cfg(feature = "alloc")]
            let b: Dynamic<Vec<u8>> = right.into();

            #[cfg(feature = "alloc")]
            assert!(!a.ct_eq_hash(&b), "False positive detected");
            #[cfg(feature = "alloc")]
            assert!(!a.ct_eq_auto(&b, None));
        }
    }

    // -------------------------------------------------------------------------
    // Consistency between ct_eq_hash and ct_eq_auto(None)
    // -------------------------------------------------------------------------

    #[cfg(feature = "alloc")]
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

        #[cfg(feature = "alloc")]
        for data in cases {
            let a: Dynamic<Vec<u8>> = data.clone().into();
            #[cfg(feature = "alloc")]
            let mut b: Dynamic<Vec<u8>> = data.into();

            #[cfg(feature = "alloc")]
            // equal
            assert_eq!(a.ct_eq_hash(&b), a.ct_eq_auto(&b, None));

            #[cfg(feature = "alloc")]
            // mutate last byte → unequal
            b.with_secret_mut(|s| {
                if !s.is_empty() {
                    let last = s.len() - 1;
                    s[last] = s[last].wrapping_add(1);
                }
            });
            assert_eq!(a.ct_eq_hash(&b), a.ct_eq_auto(&b, None));
            if !b.is_empty() {
                assert!(!a.ct_eq_hash(&b));
            }
        }
    }

    #[test]
    fn basic_equal_fixed_tiny() {
        let a = Fixed::new([0u8; 1]);
        let b = Fixed::new([0u8; 1]);
        let c = Fixed::new([1u8; 1]);
        assert!(a.ct_eq_hash(&b));
        assert!(a.ct_eq_auto(&b, None)); // should use ct_eq
        assert!(!a.ct_eq_auto(&c, None));
    }
}
