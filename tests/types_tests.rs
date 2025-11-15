// tests/types.rs

use secure_gate::{secure, Secure, SecureBytes, SecureKey32, SecurePassword, SecureStr};
use std::format;

#[test]
fn test_macro_array() {
    let key: Secure<[u8; 4]> = secure!([u8; 4], [1, 2, 3, 4]);
    assert_eq!(key.expose(), &[1, 2, 3, 4]);
}

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
    assert_eq!(pw1.expose().as_str(), "test");
    let pw2: SecurePassword = "another".to_string().into();
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
    assert_eq!(pw1.expose().as_str(), "original");
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
