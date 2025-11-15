// =================================================================================
// tests/types_tests.rs
// =================================================================================

use secrecy::ExposeSecret;
use secrecy::ExposeSecretMut;
use secure_gate::{SecureBytes, SecureKey32, SecurePassword, SecurePasswordMut, SecureStr};
use std::format;

#[test]
fn test_secure_bytes() {
    let bytes: SecureBytes = vec![0xAA, 0xBB].into();
    assert_eq!(bytes.expose(), b"\xAA\xBB");
    let cloned = bytes.clone();
    assert_eq!(cloned.expose(), b"\xAA\xBB");
}

#[test]
fn test_secure_str() {
    let s: SecureStr = "hello".parse().unwrap();
    assert_eq!(s.expose(), "hello");
    let from_str: SecureStr = "world".into();
    assert_eq!(from_str.expose(), "world");
}

#[test]
fn test_secure_key() {
    let key: SecureKey32 = [0u8; 32].into();
    assert_eq!(key.expose(), &[0u8; 32]);
}

#[test]
fn test_secure_password_creation() {
    let pw1: SecurePassword = "test".into();
    assert_eq!(pw1.expose().expose_secret(), "test");
    let pw2: SecurePassword = "another".to_string().into();
    assert_eq!(pw2.expose().expose_secret(), "another");
}

#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_mut_creation() {
    let pw: SecurePasswordMut = "test".into();
    assert_eq!(pw.expose().expose_secret(), "test");
    let pw2: SecurePasswordMut = "another".to_string().into();
    assert_eq!(pw2.expose().expose_secret(), "another");
}

#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_mut_expose_and_mutate() {
    let mut pw: SecurePasswordMut = "secret".into();
    assert_eq!(pw.expose().expose_secret(), "secret");
    pw.expose_mut().expose_secret_mut().push_str("changed");
    assert_eq!(pw.expose().expose_secret(), "secretchanged");
}

#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_clone() {
    let pw1: SecurePassword = "original".into();
    let pw2 = pw1.clone();
    assert_eq!(pw2.expose().expose_secret(), "original");
    assert_eq!(pw1.expose().expose_secret(), "original");
}

#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_default() {
    let pw: SecurePassword = SecurePassword::default();
    assert_eq!(pw.expose().expose_secret(), "");
}

#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_debug_redacted() {
    let pw: SecurePassword = "hunter2".into();
    let debug = format!("{pw:?}");
    assert!(debug.contains("[REDACTED]"), "Debug must redact: {debug}");
}
