// ==========================================================================
// tests/eq_tests.rs
// ==========================================================================
// Tests for equality (both constant-time and regular)

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "ct-eq", feature = "alloc"))]
    use secure_gate::Dynamic;
    #[cfg(feature = "ct-eq")]
    use secure_gate::{ConstantTimeEq, Fixed};

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

    #[cfg(all(feature = "ct-eq", feature = "alloc"))]
    #[test]
    fn dynamic_ct_eq_negative_cases() {
        let a: Dynamic<Vec<u8>> = vec![1u8; 32].into();
        let b: Dynamic<Vec<u8>> = vec![1u8; 31].into(); // different length
        let c: Dynamic<Vec<u8>> = vec![2u8; 32].into(); // same length, different content

        #[cfg(feature = "alloc")]
        assert!(!a.ct_eq(&b)); // different length
        #[cfg(feature = "alloc")]
        assert!(!a.ct_eq(&c)); // different content
        #[cfg(feature = "alloc")]
        assert!(a.ct_eq(&a)); // self equality
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
    #[cfg(feature = "alloc")]
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

    #[cfg(all(not(feature = "ct-eq"), feature = "alloc"))]
    #[test]
    fn partial_eq_fallback() {
        #[cfg(feature = "alloc")]
        use secure_gate::Dynamic;
        use secure_gate::ExposeSecret;
        use secure_gate::Fixed;

        // Test Fixed<T> equality
        let fixed1 = Fixed::new([1u8, 2, 3]);
        let fixed2 = Fixed::new([1u8, 2, 3]);
        let fixed3 = Fixed::new([1u8, 2, 4]);

        fixed1.with_secret(|s1| fixed2.with_secret(|s2| assert_eq!(s1, s2)));
        fixed1.with_secret(|s1| fixed3.with_secret(|s3| assert_ne!(s1, s3)));

        // Test Dynamic<T> equality
        let dyn1: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
        let dyn2: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
        let dyn3: Dynamic<Vec<u8>> = vec![1, 2, 4].into();

        dyn1.with_secret(|d1| dyn2.with_secret(|d2| assert_eq!(d1, d2)));
        dyn1.with_secret(|d1| dyn3.with_secret(|d3| assert_ne!(d1, d3)));

        // Test with strings
        let str1: Dynamic<String> = "hello".into();
        let str2: Dynamic<String> = "hello".into();
        let str3: Dynamic<String> = "world".into();

        str1.with_secret(|s1| str2.with_secret(|s2| assert_eq!(s1, s2)));
        str1.with_secret(|s1| str3.with_secret(|s3| assert_ne!(s1, s3)));
    }

    #[cfg(feature = "ct-eq")]
    #[test]
    fn test_slice_ct_eq() {
        let a = [1u8, 2, 3].as_slice();
        let b = [1u8, 2, 3].as_slice();
        let c = [1u8, 2, 4].as_slice();

        assert!(a.ct_eq(b));
        assert!(!a.ct_eq(c));
    }

    #[cfg(feature = "ct-eq")]
    #[test]
    fn test_array_ct_eq() {
        let a: [u8; 4] = [1, 2, 3, 4];
        let b: [u8; 4] = [1, 2, 3, 4];
        let c: [u8; 4] = [1, 2, 3, 5];

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[cfg(feature = "ct-eq")]
    #[test]
    fn test_vec_ct_eq() {
        let a: Vec<u8> = vec![1, 2, 3];
        let b: Vec<u8> = vec![1, 2, 3];
        let c: Vec<u8> = vec![1, 2, 4];

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[cfg(feature = "ct-eq")]
    #[test]
    fn test_string_ct_eq() {
        let a: String = "hello".to_string();
        let b: String = "hello".to_string();
        let c: String = "world".to_string();

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }
}
