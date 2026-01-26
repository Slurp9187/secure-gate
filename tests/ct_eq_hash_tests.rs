// ==========================================================================
// tests/ct_eq_hash_tests.rs
// ==========================================================================
// Tests for hash-based equality (Blake3) for large/variable secrets

#[cfg(all(test, feature = "ct-eq-hash"))]
mod ct_eq_hash_tests {
    #[cfg(feature = "alloc")]
    use secure_gate::Dynamic;
    use secure_gate::{ConstantTimeEqExt, Fixed};

    // -------------------------------------------------------------------------
    // Basic correctness – same type, same length
    // -------------------------------------------------------------------------

    #[test]
    fn basic_equal_fixed() {
        let a = Fixed::new([17u8; 23]);
        let b = Fixed::new([17u8; 23]);
        assert!(a.ct_eq_hash(&b));
    }

    #[test]
    fn basic_unequal_fixed_same_length() {
        let a = Fixed::new([17u8; 23]);
        let b = Fixed::new([18u8; 23]);
        assert!(!a.ct_eq_hash(&b));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn basic_equal_dynamic_vec() {
        let a: Dynamic<Vec<u8>> = vec![99u8; 0].into(); // empty
        let b: Dynamic<Vec<u8>> = vec![99u8; 0].into();
        assert!(a.ct_eq_hash(&b));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn basic_equal_dynamic_string() {
        let a: Dynamic<String> = "café".into();
        let b: Dynamic<String> = "café".into();
        assert!(a.ct_eq_hash(&b));
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
    fn length_mismatch_fixed() {
        let _a = Fixed::new([0u8; 32]);
        let _b = Fixed::new([0u8; 16]); // different array size → different T
                                        // This should not even compile in real usage if types differ
                                        // But if you ever allow comparing different Fixed sizes, this would fail
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
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn empty_vs_non_empty() {
        let empty: Dynamic<Vec<u8>> = vec![].into();
        let one_byte: Dynamic<Vec<u8>> = vec![0].into();
        assert!(!empty.ct_eq_hash(&one_byte));
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
        }
    }

    #[test]
    fn basic_equal_fixed_tiny() {
        let a = Fixed::new([0u8; 1]);
        let b = Fixed::new([0u8; 1]);
        let _c = Fixed::new([1u8; 1]);
        assert!(a.ct_eq_hash(&b));
    }
}
