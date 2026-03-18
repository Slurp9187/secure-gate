//! ct_eq_suite/hash.rs — Hash-based constant-time equality tests

#[cfg(all(test, feature = "ct-eq-hash"))]
mod ct_eq_hash_tests {
    #[cfg(feature = "alloc")]
    use secure_gate::Dynamic;
    use secure_gate::{ConstantTimeEqExt, Fixed};

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
        let a: Dynamic<Vec<u8>> = vec![99u8; 0].into();
        let b: Dynamic<Vec<u8>> = vec![99u8; 0].into();
        assert!(a.ct_eq_hash(&b));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn length_mismatch_ct_eq_hash() {
        let a: Dynamic<Vec<u8>> = vec![0u8; 50].into();
        let b: Dynamic<Vec<u8>> = vec![0u8; 51].into();
        assert!(!a.ct_eq_hash(&b));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn empty_vs_non_empty() {
        let empty: Dynamic<Vec<u8>> = vec![].into();
        let one_byte: Dynamic<Vec<u8>> = vec![0].into();
        assert!(!empty.ct_eq_hash(&one_byte));
    }
}
