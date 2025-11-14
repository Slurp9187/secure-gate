#[cfg(feature = "zeroize")]
use secure_types::SecretString;
use secure_types::SecurePassword; // Import re-exported SecretString for init_with test

#[test]
fn test_secure_password_creation() {
    let pw1: SecurePassword = "test".into(); // From &str
    assert_eq!(pw1.expose().as_str(), "test");
    let pw2: SecurePassword = "another".to_string().into(); // From String
    assert_eq!(pw2.expose().as_str(), "another");
}
#[test]
fn test_secure_password_expose_and_mutate() {
    let mut pw: SecurePassword = "secret".into();
    assert_eq!(pw.expose().as_str(), "secret");
    *pw.expose_mut() = "changed".to_string().into();
    assert_eq!(pw.expose().as_str(), "changed");
}
#[test]
fn test_secure_password_clone() {
    let pw1: SecurePassword = "original".into();
    let pw2 = pw1.clone();
    assert_eq!(pw2.expose().as_str(), "original");
    assert_eq!(pw1.expose().as_str(), "original"); // Original unchanged
}
#[test]
fn test_secure_password_default() {
    let pw: SecurePassword = SecurePassword::default();
    assert_eq!(pw.expose().as_str(), "");
}
#[test]
fn test_secure_password_debug_redacted() {
    let pw: SecurePassword = "hunter2".into();
    let debug = format!("{pw:?}");
    assert!(debug.contains("[REDACTED]"), "Debug must redact: {debug}");
}
#[cfg(feature = "zeroize")]
#[test]
fn test_secure_password_zeroize() {
    use zeroize::Zeroize;
    let mut pw: SecurePassword = "secret".into();
    assert_eq!(pw.expose().as_str(), "secret");
    pw.zeroize();
    // FIXED: zeroize clears len=0 (via Vec::clear() after zeroing elements/capacity)
    // All bytes zeroed up to original capacity (heap wiped); now empty string
    assert!(pw.expose().as_bytes().iter().all(|&b| b == 0)); // Vacuous for empty
    assert_eq!(pw.expose().len(), 0); // Len cleared (correct behavior)
    assert_eq!(pw.expose().as_str(), ""); // FIXED: Use .as_str() for comparison
}
#[test]
#[cfg(all(feature = "serde", feature = "zeroize"))]
fn test_secure_password_serde_roundtrip() {
    let original = "secret123";
    let pw: SecurePassword = original.into();
    let json = serde_json::to_string(&pw).unwrap(); // Serializes via Secure<SecretString>::Serialize
    assert_eq!(json, r#""secret123""#);
    let round: SecurePassword = serde_json::from_str(&json).unwrap();
    assert_eq!(round.expose().as_str(), original);
}
#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_cloneable_secret() {
    // Verifies init_with works via CloneableSecret (from SecretString)
    let pw: SecurePassword = SecurePassword::init_with(|| SecretString::from("dynamic"));
    assert_eq!(pw.expose().as_str(), "dynamic");
}
#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_finish_mut_shrink() {
    let mut pw: SecurePassword = String::with_capacity(20).into();
    pw.expose_mut().push_str("short"); // len=5, cap=20 (via DerefMut)
    assert!(pw.expose().capacity() > pw.expose().len());
    pw.finish_mut();
    assert_eq!(pw.expose().capacity(), pw.expose().len()); // Shrunk to 5
}
#[cfg(not(feature = "zeroize"))]
#[test]
fn test_secure_password_finish_mut_shrink_fallback() {
    // Fallback: No finish_mut, just mutate
    let mut pw: SecurePassword = "short".to_string().into();
    pw.expose_mut().push_str("er");
    assert_eq!(pw.expose(), "shorter");
}

#[cfg(feature = "zeroize")]
#[test]
fn test_finish_mut_noop() {
    // RENAMED: Reflects trait no-op (no downcast)
    // This tests the helper by ensuring finish_mut succeeds on Vec<String> without panic

    use secure_types::Secure;
    let mut mixed: Secure<Vec<String>> = Secure::new(vec!["a".to_string(), "b".to_string()]);
    mixed.expose_mut().push("c".to_string()); // Triggers potential re-alloc
                                              // Note: Vec<String> won't shrink (no-op via default impl)
    mixed.finish_mut(); // Should not panic (no match needed)
    assert_eq!(mixed.expose().len(), 3);
}
