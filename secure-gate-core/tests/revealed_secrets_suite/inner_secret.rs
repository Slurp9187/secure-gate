use secure_gate::{Fixed, InnerSecret, RevealSecret};

#[cfg(feature = "alloc")]
use secure_gate::Dynamic;

fn sample_fixed_inner_secret() -> InnerSecret<[u8; 4]> {
    Fixed::new([0xDEu8, 0xAD, 0xBE, 0xEF]).into_inner()
}

#[test]
fn inner_secret_needs_drop() {
    assert!(core::mem::needs_drop::<InnerSecret<[u8; 4]>>());
}

#[test]
fn inner_secret_debug_is_redacted() {
    let inner = sample_fixed_inner_secret();
    assert_eq!(format!("{inner:?}"), "[REDACTED]");
    assert_eq!(format!("{inner:#?}"), "[REDACTED]");
}

#[test]
fn inner_secret_deref_array_payload() {
    let inner = sample_fixed_inner_secret();
    assert_eq!(&*inner, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn inner_secret_into_zeroizing_array_payload() {
    let inner = sample_fixed_inner_secret();
    let protected = inner.into_zeroizing();
    assert_eq!(&*protected, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[cfg(feature = "alloc")]
#[test]
fn inner_secret_dynamic_string_payload() {
    let secret = Dynamic::<String>::new("hunter2".to_string());
    let inner: InnerSecret<String> = secret.into_inner();

    assert_eq!(format!("{inner:?}"), "[REDACTED]");
    assert_eq!(&*inner, "hunter2");
}

#[cfg(feature = "alloc")]
#[test]
fn inner_secret_dynamic_vec_payload() {
    let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
    let inner: InnerSecret<Vec<u8>> = secret.into_inner();

    assert_eq!(format!("{inner:?}"), "[REDACTED]");
    assert_eq!(&*inner, &[1, 2, 3, 4]);
}

#[cfg(feature = "alloc")]
#[test]
fn inner_secret_empty_string_edge_case() {
    let secret = Dynamic::<String>::new(String::new());
    let inner: InnerSecret<String> = secret.into_inner();

    assert_eq!(&*inner, "");
    assert!(inner.is_empty());

    let protected = inner.into_zeroizing();
    assert_eq!(&*protected, "");
    assert!(protected.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn inner_secret_empty_vec_edge_case() {
    let secret: Dynamic<Vec<u8>> = Dynamic::new(Vec::new());
    let inner: InnerSecret<Vec<u8>> = secret.into_inner();

    assert!(inner.is_empty());

    let protected = inner.into_zeroizing();
    assert!(protected.is_empty());
}
