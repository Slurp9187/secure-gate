// tests/basic_tests.rs
// Updated for secure-gate 0.4.0 — uses SecureGate<T>

extern crate alloc;
use alloc::{
    format,
    string::{String, ToString},
};
use secure_gate::{SecureGate, SecurePassword};

#[cfg(feature = "zeroize")]
use secure_gate::ExposeSecret; // ← THIS LINE WAS MISSING

#[test]
fn test_basic() {
    let pw: SecureGate<String> = SecureGate::new("test".to_string());
    assert_eq!(pw.expose(), "test");
}

#[test]
fn test_debug() {
    let pw: SecureGate<String> = SecureGate::new("hunter2".to_string());
    let debug = format!("{pw:?}");
    assert!(
        debug.contains("[REDACTED]") && debug.starts_with("Secure"),
        "Debug output should be redacted and start with 'Secure', got: {debug}"
    );
}

#[test]
fn test_expose_secret() {
    let pw: SecureGate<String> = SecureGate::new("secret".to_string());
    assert_eq!(pw.expose(), "secret");
}

#[test]
fn test_expose_secret_mut() {
    let mut pw: SecureGate<String> = SecureGate::new("secret".to_string());
    *pw.expose_mut() = "changed".to_string();
    assert_eq!(pw.expose(), "changed");
}

#[test]
fn test_clone() {
    let pw1: SecureGate<String> = SecureGate::new("original".to_string());
    let pw2 = pw1.clone();
    assert_eq!(pw2.expose(), "original");
}

#[test]
fn test_default() {
    let pw: SecureGate<String> = SecureGate::default();
    assert_eq!(pw.expose(), "");
}

#[test]
fn test_into_inner() {
    let pw: SecureGate<String> = SecureGate::new("value".to_string());
    let inner: Box<String> = pw.into_inner();
    assert_eq!(&*inner, "value");
}

#[test]
fn test_alias() {
    let pw: SecurePassword = "alias-test".into();
    #[cfg(feature = "zeroize")]
    assert_eq!(pw.expose().expose_secret(), "alias-test");
    #[cfg(not(feature = "zeroize"))]
    assert_eq!(pw.expose(), "alias-test");
}

#[test]
fn test_init_with() {
    let pw: SecureGate<String> = SecureGate::init_with(|| "init-test".to_string());
    assert_eq!(pw.expose(), "init-test");
}
