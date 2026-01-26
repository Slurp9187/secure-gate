// ==========================================================================
// tests/ct_eq_auto.rs
// ==========================================================================
// Tests for ct_eq_auto (automatic selection between ct_eq and ct_eq_hash)

#[cfg(all(test, feature = "ct-eq-hash"))]
mod ct_eq_auto_tests {
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
        assert!(a.ct_eq_auto(&b, None));
        assert!(a.ct_eq_auto(&b, Some(10)));
        assert!(a.ct_eq_auto(&b, Some(50)));
    }

    #[test]
    fn basic_unequal_fixed_same_length() {
        let a = Fixed::new([17u8; 23]);
        let b = Fixed::new([18u8; 23]);
        assert!(!a.ct_eq_auto(&b, None));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn basic_equal_dynamic_vec() {
        let a: Dynamic<Vec<u8>> = vec![99u8; 0].into(); // empty
        let b: Dynamic<Vec<u8>> = vec![99u8; 0].into();
        assert!(a.ct_eq_auto(&b, None));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn basic_equal_dynamic_string() {
        let a: Dynamic<String> = "café".into();
        let b: Dynamic<String> = "café".into();
        assert!(a.ct_eq_auto(&b, None));
    }

    // -------------------------------------------------------------------------
    // Length mismatch handling (critical for ct_eq_auto)
    // -------------------------------------------------------------------------

    #[test]
    #[cfg(feature = "alloc")]
    fn length_mismatch_ct_eq_auto() {
        let a: Dynamic<Vec<u8>> = vec![0u8; 50].into();
        let b: Dynamic<Vec<u8>> = vec![0u8; 51].into();
        assert!(!a.ct_eq_auto(&b, None));
        assert!(!a.ct_eq_auto(&b, Some(0)));
        assert!(!a.ct_eq_auto(&b, Some(1000)));
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
        assert!(a.ct_eq_auto(&b, None));
        assert!(a.ct_eq_auto(&b, Some(0)));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn empty_vs_non_empty() {
        let empty: Dynamic<Vec<u8>> = vec![].into();
        let one_byte: Dynamic<Vec<u8>> = vec![0].into();
        assert!(!empty.ct_eq_auto(&one_byte, None));
    }

    // -------------------------------------------------------------------------
    // Consistency between ct_eq_auto(None) and ct_eq/ct_eq_hash based on size
    // -------------------------------------------------------------------------

    #[cfg(feature = "alloc")]
    #[test]
    fn ct_eq_auto_consistency_with_manual() {
        let small_data = vec![0xBBu8; 16];
        let a_small: Dynamic<Vec<u8>> = small_data.clone().into();
        let b_small: Dynamic<Vec<u8>> = small_data.into();

        // Small data: ct_eq_auto(None) should match ct_eq
        assert_eq!(a_small.ct_eq_auto(&b_small, None), a_small.ct_eq(&b_small));

        let large_data = vec![0xCCu8; 64];
        let a_large: Dynamic<Vec<u8>> = large_data.clone().into();
        let b_large: Dynamic<Vec<u8>> = large_data.into();

        // Large data: ct_eq_auto(None) should match ct_eq_hash
        assert_eq!(
            a_large.ct_eq_auto(&b_large, None),
            a_large.ct_eq_hash(&b_large)
        );
    }

    #[test]
    fn basic_equal_fixed_tiny() {
        let a = Fixed::new([0u8; 1]);
        let b = Fixed::new([0u8; 1]);
        let c = Fixed::new([1u8; 1]);
        assert!(a.ct_eq_auto(&b, None)); // should use ct_eq
        assert!(!a.ct_eq_auto(&c, None));
    }
}
