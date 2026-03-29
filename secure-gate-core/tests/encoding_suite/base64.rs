//! encoding_suite/base64.rs — base64url encoding/decoding tests

#[cfg(feature = "encoding-base64")]
use secure_gate::{RevealSecret, Fixed, FromBase64UrlStr, ToBase64Url};
#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
use secure_gate::Dynamic;

#[cfg(feature = "encoding-base64")]
#[test]
fn test_slice_to_base64url() {
    let input = b"hello";
    let encoded = input.to_base64url();
    let decoded = encoded.try_from_base64url().expect("valid base64url");
    assert_eq!(decoded, b"hello");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn slice_to_base64url_zeroizing() {
    let encoded = b"hello".to_base64url_zeroizing();
    assert_eq!(&*encoded, "aGVsbG8");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn fixed_to_base64url_zeroizing_matches_plain() {
    let secret = Fixed::new([7u8; 32]);
    let plain = secret.to_base64url();
    let zeroizing = secret.to_base64url_zeroizing();
    assert_eq!(&*zeroizing, plain.as_str());
}

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
#[test]
fn dynamic_to_base64url_zeroizing_matches_plain() {
    let secret: Dynamic<Vec<u8>> = vec![10, 20, 30].into();
    let plain = secret.to_base64url();
    let zeroizing = secret.to_base64url_zeroizing();
    assert_eq!(&*zeroizing, plain.as_str());
}

#[cfg(feature = "encoding-base64")]
#[test]
fn fixed_to_base64url_zeroizing_debug_is_redacted() {
    let secret = Fixed::new([0x42u8; 4]);
    let encoded = secret.to_base64url_zeroizing();
    assert_eq!(format!("{encoded:?}"), "[REDACTED]");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn fixed_to_base64url_zeroizing_empty() {
    let empty: [u8; 0] = [];
    let encoded = empty.to_base64url_zeroizing();
    assert!(encoded.is_empty());
    assert_eq!(&*encoded, "");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn fixed_to_base64url_zeroizing_all_zeros() {
    let secret = Fixed::new([0u8; 3]);
    let encoded = secret.to_base64url_zeroizing();
    assert_eq!(&*encoded, "AAAA");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn fixed_try_from_base64url_roundtrip() {
    let fixed = Fixed::new([7u8; 32]);
    let encoded = fixed.to_base64url();
    let decoded = Fixed::<[u8; 32]>::try_from_base64url(&encoded).expect("valid");
    decoded.with_secret(|d| assert_eq!(d, &[7u8; 32]));
}

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
#[test]
fn dynamic_try_from_base64url_roundtrip() {
    let dynv: Dynamic<Vec<u8>> = vec![10, 20, 30].into();
    let encoded = dynv.to_base64url();
    let decoded = Dynamic::<Vec<u8>>::try_from_base64url(&encoded).expect("valid");
    decoded.with_secret(|d| assert_eq!(d, &[10, 20, 30]));
}

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
#[test]
fn dynamic_try_from_base64url_invalid_input_returns_err() {
    assert!(Dynamic::<Vec<u8>>::try_from_base64url("not valid base64url!!!").is_err());
}
