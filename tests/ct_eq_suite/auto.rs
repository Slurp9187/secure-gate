//! ct_eq_suite/auto.rs — Automatic ct_eq/ct_eq_hash switching tests

#[cfg(all(test, feature = "ct-eq-hash"))]
mod ct_eq_auto_tests {
    #[cfg(feature = "alloc")]
    use secure_gate::Dynamic;
    use secure_gate::{ConstantTimeEq, ConstantTimeEqExt, Fixed};

    #[test]
    fn basic_equal_fixed() {
        let a = Fixed::new([17u8; 23]);
        let b = Fixed::new([17u8; 23]);
        assert!(a.ct_eq_auto(&b, None));
        assert!(a.ct_eq_auto(&b, Some(10)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn ct_eq_auto_exact_threshold_boundary() {
        let data = vec![0xA5u8; 32];
        let a: Dynamic<Vec<u8>> = data.clone().into();
        let b: Dynamic<Vec<u8>> = data.into();

        assert!(a.ct_eq_auto(&b, Some(31)));
        assert!(a.ct_eq_auto(&b, Some(32)));
        assert!(a.ct_eq_auto(&b, Some(33)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn ct_eq_auto_consistency_with_manual() {
        let small_data = vec![0xBBu8; 16];
        let a_small: Dynamic<Vec<u8>> = small_data.clone().into();
        let b_small: Dynamic<Vec<u8>> = small_data.into();
        assert_eq!(a_small.ct_eq_auto(&b_small, None), a_small.ct_eq(&b_small));

        let large_data = vec![0xCCu8; 64];
        let a_large: Dynamic<Vec<u8>> = large_data.clone().into();
        let b_large: Dynamic<Vec<u8>> = large_data.into();
        assert_eq!(
            a_large.ct_eq_auto(&b_large, None),
            a_large.ct_eq_hash(&b_large)
        );
    }
}
