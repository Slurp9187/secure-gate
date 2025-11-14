use secure_gate::secure;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_secure_password() {
        let pw = secure!(String, "test".into());
        assert_eq!(pw.expose(), "test");
    }
    #[test]
    #[cfg(feature = "zeroize")]
    fn test_init_with() {
        use secure_gate::Secure;
        let val = Secure::<u32>::init_with(|| 42u32);
        assert_eq!(*val.expose(), 42);
    }
    #[test]
    #[cfg(feature = "serde")]
    fn test_deserialize() {
        use secure_gate::SecurePassword;
        let json = r#""secret""#;
        let pw: SecurePassword = serde_json::from_str(json).unwrap();
        // FIXED: Use .as_str() for comparison
        assert_eq!(pw.expose().as_str(), "secret");
    }
}
