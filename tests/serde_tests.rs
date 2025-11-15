// tests/serde.rs

#[cfg(feature = "serde")]
mod tests {
    use secure_gate::SecurePassword;

    #[test]
    fn test_deserialize() {
        let json = r#""secret""#;
        let pw: SecurePassword = serde_json::from_str(json).unwrap();
        assert_eq!(pw.expose().as_str(), "secret");
    }

    #[test]
    fn test_serde_roundtrip_expose() {
        let original = "secret123";
        let pw: SecurePassword = original.into();
        let json = serde_json::to_string(&pw.expose()).unwrap();
        assert_eq!(json, r#""secret123""#);
        let round: SecurePassword = serde_json::from_str(&json).unwrap();
        assert_eq!(round.expose().as_str(), original);
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn test_secure_password_serde_roundtrip() {
        let original = "secret123";
        let pw: SecurePassword = original.into();
        let json = serde_json::to_string(&pw).unwrap();
        assert_eq!(json, r#""secret123""#);
        let round: SecurePassword = serde_json::from_str(&json).unwrap();
        assert_eq!(round.expose().as_str(), original);
    }
}
