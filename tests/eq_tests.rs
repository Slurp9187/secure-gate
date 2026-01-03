// ==========================================================================
// tests/eq_tests.rs
// ==========================================================================
// Tests for constant-time equality trait.

#![cfg(feature = "ct-eq")]

#[cfg(test)]

mod tests {
    use secure_gate::eq::ConstantTimeEq;

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

    #[test]
    fn slice_ct_eq_empty() {
        // Empty slices
        assert!(([0u8; 0]).as_slice().ct_eq(&[]));
        assert!(!([0u8; 0]).as_slice().ct_eq(&[1]));
        assert!(![1u8].as_slice().ct_eq(&[]));
    }

    #[test]
    fn array_ct_eq_basic() {
        // Equal
        assert!([1u8, 2, 3].ct_eq(&[1, 2, 3]));

        // Not equal
        assert!(![1u8, 2, 3].ct_eq(&[1, 2, 4]));
    }

    #[test]
    fn array_ct_eq_edge_cases() {
        // All zeros
        assert!([0u8; 4].ct_eq(&[0u8; 4]));
        assert!(![0u8; 4].as_slice().ct_eq(&[0u8; 3])); // Different lengths via slice
    }

    #[test]
    fn large_arrays() {
        let a = [42u8; 1000];
        let b = [42u8; 1000];
        let c = [43u8; 1000];

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }
}
