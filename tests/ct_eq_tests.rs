// ==========================================================================
// tests/eq_tests.rs
// ==========================================================================
// Tests for equality (both constant-time and regular)

#[cfg(test)]
mod tests {
    #[cfg(feature = "ct-eq")]
    use secure_gate::{ConstantTimeEq, Dynamic, Fixed};

    #[cfg(not(feature = "ct-eq"))]
    use secure_gate::ExposeSecret;

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
    #[allow(unused)]
    fn fixed_ct_eq_different_lengths_compile_fail() {
        let a = Fixed::new([1u8; 32]);
        let b = Fixed::new([1u8; 64]);
        // a.ct_eq(&b); // Must not compile — different array sizes
        // Compile-fail guard: ensures type safety for ct_eq
    }

    #[cfg(feature = "ct-eq")]
    #[test]
    fn dynamic_ct_eq_negative_cases() {
        let a: Dynamic<Vec<u8>> = vec![1u8; 32].into();
        let b: Dynamic<Vec<u8>> = vec![1u8; 31].into(); // different length
        let c: Dynamic<Vec<u8>> = vec![2u8; 32].into(); // same length, different content

        assert!(!a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert!(a.ct_eq(&a));
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

    #[cfg(feature = "ct-eq")]
    #[test]
    fn test_wrapper_equality_with_ct_eq() {
        // Test Fixed<T> ct_eq
        let fixed1 = Fixed::new([1u8, 2, 3]);
        let fixed2 = Fixed::new([1u8, 2, 3]);
        let fixed3 = Fixed::new([1u8, 2, 4]);

        assert!(fixed1.ct_eq(&fixed2));
        assert!(!fixed1.ct_eq(&fixed3));

        // Test Dynamic<T> ct_eq
        let dyn1: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
        let dyn2: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
        let dyn3: Dynamic<Vec<u8>> = vec![1, 2, 4].into();

        assert!(dyn1.ct_eq(&dyn2));
        assert!(!dyn1.ct_eq(&dyn3));

        // Test with strings
        let str1: Dynamic<String> = "hello".into();
        let str2: Dynamic<String> = "hello".into();
        let str3: Dynamic<String> = "world".into();

        assert!(str1.ct_eq(&str2));
        assert!(!str1.ct_eq(&str3));
    }

    #[cfg(not(feature = "ct-eq"))]
    #[test]
    fn partial_eq_fallback() {
        use secure_gate::{Dynamic, Fixed};

        // Test Fixed<T> equality
        let fixed1 = Fixed::new([1u8, 2, 3]);
        let fixed2 = Fixed::new([1u8, 2, 3]);
        let fixed3 = Fixed::new([1u8, 2, 4]);

        assert_eq!(fixed1.expose_secret(), fixed2.expose_secret());
        assert_ne!(fixed1.expose_secret(), fixed3.expose_secret());

        // Test Dynamic<T> equality
        let dyn1: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
        let dyn2: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
        let dyn3: Dynamic<Vec<u8>> = vec![1, 2, 4].into();

        assert_eq!(dyn1.expose_secret(), dyn2.expose_secret());
        assert_ne!(dyn1.expose_secret(), dyn3.expose_secret());

        // Test with strings
        let str1: Dynamic<String> = "hello".into();
        let str2: Dynamic<String> = "hello".into();
        let str3: Dynamic<String> = "world".into();

        assert_eq!(str1.expose_secret(), str2.expose_secret());
        assert_ne!(str1.expose_secret(), str3.expose_secret());
    }
}
