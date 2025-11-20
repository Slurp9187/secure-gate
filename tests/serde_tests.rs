// tests/serde_tests.rs
// Updated for secure-gate 0.4.0 — correct expose_secret usage

#[cfg(feature = "serde")]
use secrecy::ExposeSecret;
#[cfg(feature = "serde")]
use secure_gate::SecurePassword;

#[cfg(feature = "serde")]
#[test]
fn test_deserialize() {
    let json = r#""secret""#;
    let pw: SecurePassword = serde_json::from_str(json).unwrap();
    #[cfg(feature = "zeroize")]
    assert_eq!(pw.expose().expose_secret(), "secret");
    #[cfg(not(feature = "zeroize"))]
    assert_eq!(pw.expose(), "secret");
}

#[cfg(feature = "serde")]
#[test]
fn test_serde_roundtrip_expose() {
    let original = "secret123";
    let pw: SecurePassword = original.into();
    #[cfg(feature = "zeroize")]
    let json = serde_json::to_string(pw.expose().expose_secret()).unwrap();
    #[cfg(not(feature = "zeroize"))]
    let json = serde_json::to_string(pw.expose()).unwrap();
    assert_eq!(json, r#""secret123""#);
    let round: SecurePassword = serde_json::from_str(&json).unwrap();
    #[cfg(feature = "zeroize")]
    assert_eq!(round.expose().expose_secret(), original);
    #[cfg(not(feature = "zeroize"))]
    assert_eq!(round.expose(), original);
}

#[cfg(all(feature = "serde", feature = "zeroize"))]
#[test]
fn test_secure_password_serde_roundtrip() {
    let original = "secret123";
    let pw: SecurePassword = original.into();
    let json = serde_json::to_string(pw.expose().expose_secret()).unwrap();
    assert_eq!(json, r#""secret123""#);
    let round: SecurePassword = serde_json::from_str(&json).unwrap();
    assert_eq!(round.expose().expose_secret(), original);
}
