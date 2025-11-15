// tests/basic.rs

extern crate alloc;
use alloc::{
    format,
    string::{String, ToString},
};
use secure_gate::{ExposeSecret, ExposeSecretMut, Secure};
// use secure_gate::SecurePassword;
// use secure_gate::secure;

#[test]
fn test_basic() {
    let pw: Secure<String> = Secure::new("test".to_string());
    assert_eq!(pw.expose(), "test");
}

#[test]
fn test_debug() {
    let pw: Secure<String> = Secure::new("hunter2".to_string());
    let debug = format!("{pw:?}");
    assert!(
        debug.contains("[REDACTED]") && debug.starts_with("Secure"),
        "Debug output should be redacted and start with 'Secure', got: {debug}"
    );
}

#[test]
fn test_expose_secret() {
    let pw: Secure<String> = Secure::new("secret".to_string());
    assert_eq!(pw.expose_secret(), "secret");
}

#[test]
fn test_expose_secret_mut() {
    let mut pw: Secure<String> = Secure::new("secret".to_string());
    *pw.expose_secret_mut() = "changed".to_string();
    assert_eq!(pw.expose_secret(), "changed");
}

#[test]
fn test_clone() {
    let pw1: Secure<String> = Secure::new("original".to_string());
    let pw2 = pw1.clone();
    assert_eq!(pw2.expose(), "original");
}

#[test]
fn test_default() {
    let pw: Secure<String> = Secure::default();
    assert_eq!(pw.expose(), "");
}

#[test]
fn test_into_inner() {
    let pw: Secure<String> = Secure::new("value".to_string());
    let inner: Box<String> = pw.into_inner();
    assert_eq!(&*inner, "value");
}

#[test]
fn test_init_with() {
    let pw: Secure<String> = Secure::init_with(|| "init-test".to_string());
    assert_eq!(pw.expose(), "init-test");
}
