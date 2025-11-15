// tests/macros.rs

use secure_gate::{secure, Secure};

#[test]
fn test_macro() {
    let pw: Secure<String> = secure!(String, "macro-test".to_string());
    assert_eq!(pw.expose(), "macro-test");
}

#[test]
fn test_macro_array() {
    let key: Secure<[u8; 4]> = secure!([u8; 4], [1, 2, 3, 4]);
    assert_eq!(key.expose(), &[1, 2, 3, 4]);
}

#[test]
fn test_secure_password() {
    let pw = secure!(String, "test".into());
    assert_eq!(pw.expose(), "test");
}
