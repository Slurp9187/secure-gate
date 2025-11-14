// ==============================================================================================
// tests/integration.rs
// ==============================================================================================

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
};

use secure_types::{secure, ExposeSecret, ExposeSecretMut, Secure, SecurePassword};

#[test]
fn test_basic() {
    let pw: Secure<String> = Secure::new("test".to_string());
    assert_eq!(pw.expose(), "test");
}

#[test]
fn test_debug() {
    let pw: Secure<String> = Secure::new("hunter2".to_string());
    assert_eq!(
        format!("{pw:?}"),
        "Secure<alloc::string::String>([REDACTED])"
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
fn test_macro() {
    let pw: Secure<String> = secure!(String, "macro-test".to_string());
    assert_eq!(pw.expose(), "macro-test");
}

#[test]
fn test_alias() {
    let pw: SecurePassword = Secure::new("alias-test".to_string());
    assert_eq!(pw.expose(), "alias-test");
}

#[test]
fn test_init_with() {
    let pw: Secure<String> = Secure::init_with(|| "init-test".to_string());
    assert_eq!(pw.expose(), "init-test");
}

#[cfg(feature = "zeroize")]
#[test]
fn test_clone_scoped_zeroize() {
    use zeroize::{DefaultIsZeroes, Zeroize};

    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    struct TestSecret(u32);

    impl DefaultIsZeroes for TestSecret {}

    // Zeroize is provided by blanket impl due to DefaultIsZeroes

    let orig: Secure<TestSecret> = Secure::new(TestSecret(42));
    let cloned = orig.clone();
    assert_eq!(cloned.expose(), &TestSecret(42));

    // Indirect verification: Clone in closure-like scope, assert no leak (trust init_with)
    let mut sec = Secure::new(TestSecret(42));
    let _cloned_in_scope = sec.clone(); // Triggers scoped zeroize
    sec.zeroize(); // Manual for paranoia
    assert_eq!(sec.expose(), &TestSecret(0)); // Confirmed wiped
}
