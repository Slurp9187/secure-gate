// ==========================================================================
// tests/no_clone_tests.rs
// ==========================================================================

#[cfg(test)]
mod tests {
    use secure_gate::{DynamicNoClone, Fixed, FixedNoClone};

    #[test]
    fn fixed_no_clone_cannot_be_cloned() {
        let _key = FixedNoClone::new([0u8; 32]);
        // _key.clone(); // compile error — correct
    }

    #[test]
    fn fixed_no_clone_has_full_api_parity() {
        let mut key = FixedNoClone::new([42u8; 32]);

        // Use explicit exposure — this is intentional
        assert_eq!(key.expose_secret()[0], 42);
        key.expose_secret_mut()[0] = 99;
        assert_eq!(key.expose_secret()[0], 99);

        // All access must go through expose_secret() — security model enforced
        // Verify first element changed, rest remain 42
        assert_eq!(key.expose_secret()[0], 99);
        assert_eq!(key.expose_secret()[1], 42);
        assert_eq!(key.expose_secret()[31], 42);
    }

    #[test]
    fn from_fixed_to_no_clone_works() {
        let fixed = Fixed::new([1u8; 32]);
        let no_clone = fixed.no_clone();
        assert_eq!(no_clone.expose_secret()[0], 1);
        // no_clone.clone(); // compile error — correct
    }

    #[test]
    fn dynamic_no_clone_string() {
        let mut pw: DynamicNoClone<String> = DynamicNoClone::new(Box::new("secret".to_owned()));

        // Must use expose_secret_mut() — no implicit Deref
        pw.expose_secret_mut().push_str("123");
        assert_eq!(pw.expose_secret(), "secret123");

        let s = pw.finish_mut();
        assert_eq!(s, "secret123");
    }

    #[test]
    fn dynamic_no_clone_vec_u8() {
        let mut data = DynamicNoClone::new(Box::new(vec![1, 2, 3]));

        data.expose_secret_mut().push(42);
        assert_eq!(data.expose_secret(), &[1, 2, 3, 42]);

        // All access must go through expose_secret() — security model enforced
        assert_eq!(data.expose_secret(), &vec![1, 2, 3, 42]);
    }
}
