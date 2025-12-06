// ==========================================================================
// tests/integration.rs
// ==========================================================================
// Core integration tests — no macro usage here, pure v0.6.0 API

use secure_gate::{Dynamic, Fixed};

#[test]
fn basic_usage_explicit_access() {
    let mut key = Fixed::new([0u8; 32]);
    let mut pw = Dynamic::<String>::new("hunter2".to_string());

    // Fixed<[u8; N]> now has .len() and .is_empty()
    assert_eq!(key.len(), 32);
    assert!(!key.is_empty());
    assert_eq!(pw.expose_secret().len(), 7);
    assert_eq!(pw.expose_secret(), "hunter2");

    pw.expose_secret_mut().push('!');
    key.expose_secret_mut()[0] = 1;

    assert_eq!(pw.expose_secret(), "hunter2!");
    assert_eq!(key.expose_secret()[0], 1);
}

#[test]
fn fixed_is_truly_zero_cost() {
    let key = Fixed::new([0u8; 32]);
    assert_eq!(core::mem::size_of_val(&key), 32);
}

#[test]
fn debug_is_redacted() {
    let key = Fixed::new([0u8; 32]);
    let pw = Dynamic::<String>::new("hunter2".to_string());

    assert_eq!(format!("{key:?}"), "[REDACTED]");
    assert_eq!(format!("{pw:?}"), "[REDACTED]");
    assert_eq!(format!("{key:#?}"), "[REDACTED]");
    assert_eq!(format!("{pw:#?}"), "[REDACTED]");
}

#[test]
fn clone_dynamic_is_isolated() {
    let pw1 = Dynamic::<String>::new("original".to_string());
    let pw2 = pw1.clone();

    let mut pw1_mut = pw1.clone();
    pw1_mut.expose_secret_mut().push('!');

    assert_eq!(pw1.expose_secret(), "original");
    assert_eq!(pw2.expose_secret(), "original");
    assert_eq!(pw1_mut.expose_secret(), "original!");
}

#[test]
fn into_inner_extracts() {
    let key = Fixed::new([1u8; 32]);
    assert_eq!(key.into_inner(), [1u8; 32]);

    let pw = Dynamic::<String>::new("secret".to_string());
    let boxed = pw.into_inner();
    assert_eq!(&*boxed, "secret");
}

#[cfg(feature = "serde")]
#[test]
fn serde_fixed_serialize_is_blocked() {
    let key = Fixed::new([0u8; 32]);
    let err = serde_json::to_string(&key).expect_err("should not serialize");
    assert!(err
        .to_string()
        .contains("serialization of Fixed<T> is intentionally disabled"));
}

#[cfg(feature = "serde")]
#[test]
fn serde_dynamic_serialize_is_blocked() {
    let pw = Dynamic::<String>::new("hunter2".to_string());

    let err = serde_json::to_string(&pw).expect_err("Dynamic<T> must refuse serialization");

    let msg = err.to_string();
    assert!(
        msg.contains("serialization of Dynamic<T> is intentionally disabled"),
        "Error message should explain the security block. Got: {msg}"
    );
}

#[cfg(feature = "serde")]
#[test]
fn dynamic_deserialize_is_blocked_with_clear_error() {
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    struct Wrapper {
        #[allow(dead_code)]
        secret: Dynamic<String>,
    }

    let json = r#"{"secret": "hunter2"}"#;

    let err = serde_json::from_str::<Wrapper>(json).expect_err("Deserialization should fail");

    let msg = err.to_string();
    assert!(
        msg.contains("Deserialization of Dynamic<T> is intentionally disabled")
            || msg.contains("Dynamic<T> is intentionally disabled"),
        "Error message should explain security rationale. Got: {msg}"
    );
}

// REPLACED: fixed_as_ref_as_mut → explicit_access_for_byte_arrays
#[test]
fn explicit_access_for_byte_arrays() {
    let mut key = Fixed::new([42u8; 32]);

    // Immutable borrow – must be explicit
    let slice: &[u8] = key.expose_secret();
    assert_eq!(slice.len(), 32);
    assert_eq!(slice[0], 42);

    // Mutable borrow – must be explicit
    let mut_slice: &mut [u8] = key.expose_secret_mut();
    mut_slice[0] = 99;
    assert_eq!(key.expose_secret()[0], 99);
}
