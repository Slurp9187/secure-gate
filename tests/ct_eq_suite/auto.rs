//! ct_eq_suite/auto.rs — Automatic ct_eq/ct_eq_hash switching tests

#[cfg(all(test, feature = "ct-eq-hash"))]
mod ct_eq_auto_tests {
    #[cfg(feature = "alloc")]
    use secure_gate::Dynamic;
    use secure_gate::{ConstantTimeEq, ConstantTimeEqExt, Fixed, CT_EQ_AUTO_THRESHOLD};

    #[test]
    fn basic_equal_fixed() {
        let a = Fixed::new([17u8; 23]);
        let b = Fixed::new([17u8; 23]);
        assert!(a.ct_eq_auto(&b));
        assert!(a.ct_eq_auto_with_threshold(&b, 10));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn ct_eq_auto_exact_threshold_boundary() {
        let data = vec![0xA5u8; 32];
        let a: Dynamic<Vec<u8>> = data.clone().into();
        let b: Dynamic<Vec<u8>> = data.into();

        assert!(a.ct_eq_auto_with_threshold(&b, 31));
        assert!(a.ct_eq_auto_with_threshold(&b, 32));
        assert!(a.ct_eq_auto_with_threshold(&b, 33));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn ct_eq_auto_consistency_with_manual() {
        let small_data = vec![0xBBu8; 16];
        let a_small: Dynamic<Vec<u8>> = small_data.clone().into();
        let b_small: Dynamic<Vec<u8>> = small_data.into();
        assert_eq!(a_small.ct_eq_auto(&b_small), a_small.ct_eq(&b_small));

        let large_data = vec![0xCCu8; 64];
        let a_large: Dynamic<Vec<u8>> = large_data.clone().into();
        let b_large: Dynamic<Vec<u8>> = large_data.into();
        assert_eq!(
            a_large.ct_eq_auto(&b_large),
            a_large.ct_eq_hash(&b_large)
        );
    }

    #[test]
    fn ct_eq_auto_unequal_below_threshold() {
        // 16 bytes < default threshold of 32 → dispatches to ct_eq (direct path)
        let a = Fixed::new([0xAAu8; 16]);
        let b = Fixed::new([0xBBu8; 16]);
        assert!(!a.ct_eq_auto(&b));
        assert!(!a.ct_eq_auto_with_threshold(&b, 32));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn ct_eq_auto_unequal_above_threshold() {
        // 64 bytes > default threshold of 32 → dispatches to ct_eq_hash (hash path)
        let a: Dynamic<Vec<u8>> = vec![0xAAu8; 64].into();
        let b: Dynamic<Vec<u8>> = vec![0xBBu8; 64].into();
        assert!(!a.ct_eq_auto(&b));
        assert!(!a.ct_eq_auto_with_threshold(&b, 0)); // force hash path for any length
    }

    /// CT_EQ_AUTO_THRESHOLD is exported from the crate root and equals 32.
    #[test]
    fn threshold_constant_value() {
        assert_eq!(CT_EQ_AUTO_THRESHOLD, 32);
    }

    /// ct_eq_auto() is exactly equivalent to ct_eq_auto_with_threshold(CT_EQ_AUTO_THRESHOLD)
    /// for inputs below, at, and above the threshold.
    #[cfg(feature = "alloc")]
    #[test]
    fn ct_eq_auto_equals_with_threshold_default() {
        // below threshold (16 bytes)
        let a: Dynamic<Vec<u8>> = vec![0xAAu8; 16].into();
        let b: Dynamic<Vec<u8>> = vec![0xAAu8; 16].into();
        assert_eq!(
            a.ct_eq_auto(&b),
            a.ct_eq_auto_with_threshold(&b, CT_EQ_AUTO_THRESHOLD)
        );

        // at threshold (32 bytes)
        let a: Dynamic<Vec<u8>> = vec![0xBBu8; 32].into();
        let b: Dynamic<Vec<u8>> = vec![0xBBu8; 32].into();
        assert_eq!(
            a.ct_eq_auto(&b),
            a.ct_eq_auto_with_threshold(&b, CT_EQ_AUTO_THRESHOLD)
        );

        // above threshold (64 bytes)
        let a: Dynamic<Vec<u8>> = vec![0xCCu8; 64].into();
        let b: Dynamic<Vec<u8>> = vec![0xCCu8; 64].into();
        assert_eq!(
            a.ct_eq_auto(&b),
            a.ct_eq_auto_with_threshold(&b, CT_EQ_AUTO_THRESHOLD)
        );
    }

    /// Some(usize::MAX) and Some(4097) must behave identically to Some(4096)
    /// and must not panic. Tests both equal and unequal 5000-byte inputs.
    #[cfg(feature = "alloc")]
    #[test]
    fn pathological_threshold_cap() {
        // equal
        let a: Dynamic<Vec<u8>> = vec![0xDDu8; 5000].into();
        let b: Dynamic<Vec<u8>> = vec![0xDDu8; 5000].into();
        let baseline = a.ct_eq_auto_with_threshold(&b, 4096);
        assert!(baseline);
        assert_eq!(a.ct_eq_auto_with_threshold(&b, 4097),       baseline);
        assert_eq!(a.ct_eq_auto_with_threshold(&b, usize::MAX), baseline);

        // unequal
        let c: Dynamic<Vec<u8>> = vec![0xEEu8; 5000].into();
        let baseline_ne = a.ct_eq_auto_with_threshold(&c, 4096);
        assert!(!baseline_ne);
        assert_eq!(a.ct_eq_auto_with_threshold(&c, 4097),       baseline_ne);
        assert_eq!(a.ct_eq_auto_with_threshold(&c, usize::MAX), baseline_ne);
    }
}
