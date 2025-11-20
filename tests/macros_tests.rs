// tests/macros_tests.rs
// Updated for secure-gate 0.4.0 — uses SecureGate<T>

use secure_gate::{secure, SecureGate};

#[test]
fn test_macro() {
    let pw: SecureGate<String> = secure!(String, "macro-test".to_string());
    assert_eq!(pw.expose(), "macro-test");
}

#[test]
fn test_macro_array() {
    let key: SecureGate<[u8; 4]> = secure!([u8; 4], [1, 2, 3, 4]);
    assert_eq!(key.expose(), &[1, 2, 3, 4]);
}

#[test]
fn test_secure_password() {
    let pw: SecureGate<String> = secure!(String, "test".into());
    assert_eq!(pw.expose(), "test");
}
