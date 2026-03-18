//! encoding_suite/base64.rs — base64url encoding/decoding tests

#[cfg(feature = "encoding-base64")]
use secure_gate::{ExposeSecret, Fixed, FromBase64UrlStr, ToBase64Url};
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
