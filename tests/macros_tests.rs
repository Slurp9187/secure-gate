// tests/macros_tests.rs
//! Tests for all public macros — works with and without zeroize feature

#![cfg(test)]

use secure_gate::{dynamic_alias, fixed_alias, secure, Dynamic};

// Only bring in secrecy and zeroizing macros when the feature is enabled
#[cfg(feature = "zeroize")]
use secrecy::ExposeSecret;
#[cfg(feature = "zeroize")]
use secure_gate::secure_zeroizing;

#[test]
fn secure_macro_fixed_array() {
    let key = secure!([u8; 32], [42u8; 32]);
    assert_eq!(key.0, [42u8; 32]);
    assert_eq!(key.len(), 32);
}

#[test]
fn secure_macro_heap_string() {
    let pw = secure!(String, "hunter2".to_string());
    assert_eq!(&*pw, "hunter2");
}

#[test]
fn secure_macro_heap_vec_u8() {
    let data = vec![9u8; 100];
    let secret = secure!(Vec<u8>, data.clone());
    assert_eq!(&*secret, &data);
}

#[test]
fn secure_macro_heap_generic() {
    let payload = vec![0u8; 256];
    let secret: Dynamic<Vec<u8>> = secure!(heap Vec<u8>, payload.clone());
    assert_eq!(&*secret, &payload);
}

#[cfg(feature = "zeroize")]
#[test]
fn secure_zeroizing_fixed() {
    let key = secure_zeroizing!([u8; 32], [99u8; 32]);
    assert_eq!(&*key, &[99u8; 32]);
    assert_eq!(key.len(), 32);
}

#[cfg(feature = "zeroize")]
#[test]
fn secure_zeroizing_heap_string() {
    let pw = secure_zeroizing!(heap String, Box::new("top secret".to_string()));
    assert_eq!(pw.expose_secret().as_str(), "top secret");
    assert_eq!(pw.expose_secret().len(), 10);
}

#[cfg(feature = "zeroize")]
#[test]
fn secure_zeroizing_heap_vec() {
    let data = vec![7u8; 64];
    let secret = secure_zeroizing!(heap Vec<u8>, Box::new(data.clone()));
    assert_eq!(secret.expose_secret().as_slice(), &data[..]);
    assert_eq!(secret.expose_secret().len(), 64);
}

#[test]
fn fixed_alias_creates_type_and_methods() {
    fixed_alias!(MyKey, 32);
    fixed_alias!(Nonce12, 12);

    let k1 = MyKey::new([1u8; 32]);
    let k2 = MyKey::from([2u8; 32]);
    let k3 = MyKey::from_slice(&[3u8; 32]);

    assert_eq!(k1.0, [1u8; 32]);
    assert_eq!(k2.0, [2u8; 32]);
    assert_eq!(k3.0, [3u8; 32]);

    let n = Nonce12::from_slice(&[9u8; 12]);
    assert_eq!(n.0, [9u8; 12]);
}

#[test]
#[should_panic(expected = "slice length mismatch")]
fn fixed_alias_from_slice_panics_on_wrong_length() {
    fixed_alias!(BadKey, 16);
    let _ = BadKey::from_slice(&[0u8; 32]);
}

#[test]
fn dynamic_alias_creates_type() {
    dynamic_alias!(Password, String);
    dynamic_alias!(Token, Vec<u8>);

    let mut pw: Password = Dynamic::new("correct horse".to_string());
    pw.push('!');
    assert_eq!(&*pw, "correct horse!");

    let token: Token = Dynamic::new(vec![7u8; 64]);
    assert_eq!(token.len(), 64);
}

#[test]
fn macro_works_in_downstream_crates() {
    let _ = secure!([u8; 24], [0u8; 24]);
    let _ = secure!(String, "test".into());
}

#[test]
fn fixed_alias_supports_from_and_into() {
    fixed_alias!(AesKey, 32);
    fixed_alias!(Nonce, 12);

    // These are the beautiful, idiomatic patterns that actually work
    let key1 = AesKey::from([42u8; 32]);
    let key2: AesKey = [43u8; 32].into(); // .into() works!
    let key3 = AesKey::new([44u8; 32]);

    let nonce = Nonce::from([1u8; 12]);
    let nonce2: Nonce = [2u8; 12].into();

    assert_eq!(key1.0, [42u8; 32]);
    assert_eq!(key2.0, [43u8; 32]);
    assert_eq!(key3.0, [44u8; 32]);
    assert_eq!(nonce.0, [1u8; 12]);
    assert_eq!(nonce2.0, [2u8; 12]);
}
