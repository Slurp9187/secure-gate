// tests/types_tests.rs
// Updated for secure-gate 0.4.0 — fully modernized

use secure_gate::{SecureBytes, SecureKey32, SecurePassword, SecurePasswordBuilder, SecureStr};

#[cfg(feature = "zeroize")]
use secrecy::{ExposeSecret, ExposeSecretMut};

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
    #[cfg(feature = "stack")]
    assert_eq!(&*key, &[0u8; 32]);
    #[cfg(not(feature = "stack"))]
    assert_eq!(key.expose(), &[0u8; 32]);
}

#[test]
fn test_secure_password_creation() {
    let pw1: SecurePassword = "test".into();
    #[cfg(feature = "zeroize")]
    assert_eq!(pw1.expose().expose_secret(), "test");
    #[cfg(not(feature = "zeroize"))]
    assert_eq!(pw1.expose(), "test");

    let pw2: SecurePassword = "another".to_string().into();
    #[cfg(feature = "zeroize")]
    assert_eq!(pw2.expose().expose_secret(), "another");
    #[cfg(not(feature = "zeroize"))]
    assert_eq!(pw2.expose(), "another");
}

#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_builder_creation() {
    let pw: SecurePasswordBuilder = "test".into();
    assert_eq!(pw.expose().expose_secret(), "test");
    let pw2: SecurePasswordBuilder = "another".to_string().into();
    assert_eq!(pw2.expose().expose_secret(), "another");
}

#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_builder_expose_and_mutate() {
    let mut pw: SecurePasswordBuilder = "secret".into();
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

#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_builder_into_password() {
    let mut builder: SecurePasswordBuilder = "base".into();
    builder
        .expose_mut()
        .expose_secret_mut()
        .push_str("appended");
    let pw: SecurePassword = builder.into_password();
    assert_eq!(pw.expose().expose_secret(), "baseappended");
}

#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_builder_build() {
    let mut builder: SecurePasswordBuilder = "start".into();
    builder.expose_mut().expose_secret_mut().push_str("end");
    let pw: SecurePassword = builder.build();
    assert_eq!(pw.expose().expose_secret(), "startend");
}

#[test]
#[cfg(feature = "zeroize")]
fn test_secure_password_builder_zeroize_after_into() {
    let mut builder: SecurePasswordBuilder = "sensitive".into();

    let ptr = builder.expose().expose_secret().as_ptr();
    let len = builder.expose().expose_secret().len();

    let pw: SecurePassword = builder.into_password();

    assert_eq!(pw.expose().expose_secret(), "sensitive");

    unsafe {
        let slice = core::slice::from_raw_parts(ptr, len);
        assert!(
            slice.iter().all(|&b| b == 0),
            "builder memory not zeroized after into_password"
        );
    }
}
