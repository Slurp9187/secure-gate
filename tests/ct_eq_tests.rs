// ==========================================================================
// tests/eq_tests.rs
// ==========================================================================
// Tests for equality (both constant-time and regular)

#[cfg(test)]
mod tests {
    #[cfg(feature = "ct-eq")]
    use secure_gate::ct_eq::ConstantTimeEq;

    #[cfg(feature = "ct-eq")]
    #[test]
    fn slice_ct_eq_basic() {
        // Equal
        assert!([1u8, 2, 3].as_slice().ct_eq(&[1, 2, 3]));

        // Not equal
        assert!(![1u8, 2, 3].as_slice().ct_eq(&[1, 2, 4]));

        // Different lengths
        assert!(![1u8, 2, 3].as_slice().ct_eq(&[1, 2]));
        assert!(![1u8, 2].as_slice().ct_eq(&[1, 2, 3]));
    }

    #[cfg(feature = "ct-eq")]
    #[test]
    fn slice_ct_eq_empty() {
        // Empty slices
        assert!(([0u8; 0]).as_slice().ct_eq(&[]));
        assert!(!([0u8; 0]).as_slice().ct_eq(&[1]));
        assert!(![1u8].as_slice().ct_eq(&[]));
    }

    #[cfg(feature = "ct-eq")]
    #[test]
    fn array_ct_eq_basic() {
        // Equal
        assert!([1u8, 2, 3].ct_eq(&[1, 2, 3]));

        // Not equal
        assert!(![1u8, 2, 3].ct_eq(&[1, 2, 4]));
    }

    #[cfg(feature = "ct-eq")]
    #[test]
    fn array_ct_eq_edge_cases() {
        // All zeros
        assert!([0u8; 4].ct_eq(&[0u8; 4]));
        assert!(![0u8; 4].as_slice().ct_eq(&[0u8; 3])); // Different lengths via slice
    }

    #[cfg(feature = "ct-eq")]
    #[test]
    fn large_arrays() {
        let a = [42u8; 1000];
        let b = [42u8; 1000];
        let c = [43u8; 1000];

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[cfg(not(feature = "ct-eq"))]
    #[test]
    fn partial_eq_fallback() {
        use secure_gate::{Fixed, Dynamic};

        // Test Fixed<T> equality
        let fixed1 = Fixed::new([1u8, 2, 3]);
        let fixed2 = Fixed::new([1u8, 2, 3]);
        let fixed3 = Fixed::new([1u8, 2, 4]);

        assert_eq!(fixed1, fixed2);
        assert_ne!(fixed1, fixed3);

        // Test Dynamic<T> equality
        let dyn1: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
        let dyn2: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
        let dyn3: Dynamic<Vec<u8>> = vec![1, 2, 4].into();

        assert_eq!(dyn1, dyn2);
        assert_ne!(dyn1, dyn3);

        // Test with strings
        let str1: Dynamic<String> = "hello".into();
        let str2: Dynamic<String> = "hello".into();
        let str3: Dynamic<String> = "world".into();

        assert_eq!(str1, str2);
        assert_ne!(str1, str3);
    }
}
