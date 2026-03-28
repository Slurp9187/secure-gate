//! encoding_suite/bech32.rs — bech32/bech32m encoding/decoding tests

#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
use secure_gate::Bech32Error;
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
use secure_gate::Dynamic;
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
use secure_gate::RevealSecret;
#[cfg(feature = "encoding-bech32")]
use secure_gate::{FromBech32Str, ToBech32};
#[cfg(feature = "encoding-bech32m")]
use secure_gate::{FromBech32mStr, ToBech32m};

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_unchecked_roundtrip_preserves_hrp() {
    let data = b"hello world";
    let encoded = data.try_to_bech32("fuzz").expect("valid bech32");

    let (hrp, decoded) = encoded.try_from_bech32_unchecked().expect("valid bech32");
    assert_eq!(hrp, "fuzz");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_invalid_hrp_encode_fails() {
    let err = b"data".try_to_bech32("");
    assert_eq!(err, Err(Bech32Error::InvalidHrp));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_decode_malformed_fails() {
    let err = "notabech32string".try_from_bech32("fuzz");
    assert!(err.is_err());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_try_from_bech32_accepts_matching_hrp() {
    let data = b"hello world";
    let encoded = data.try_to_bech32("fuzz").expect("valid bech32");
    let decoded = encoded
        .try_from_bech32("fuzz")
        .expect("expected hrp should match");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_try_from_bech32_rejects_mismatched_hrp() {
    let data = b"hello world";
    let encoded = data.try_to_bech32("fuzz").expect("valid bech32");
    let err = encoded.try_from_bech32("other");
    assert!(err.is_err());
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bech32m_roundtrip() {
    let data = b"payload";
    let encoded = data.try_to_bech32m("fuzzm").expect("valid");
    let (hrp, decoded) = encoded.try_from_bech32m_unchecked().expect("valid bech32m");
    assert_eq!(hrp, "fuzzm");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bech32m_invalid_hrp_encode_fails() {
    let err = b"data".try_to_bech32m("");
    assert_eq!(err, Err(Bech32Error::InvalidHrp));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bech32m_decode_malformed_fails() {
    let err = "notabech32mstring".try_from_bech32m("fuzzm");
    assert!(err.is_err());
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bech32m_try_from_bech32m_accepts_matching_hrp() {
    let data = b"hello world";
    let encoded = data.try_to_bech32m("fuzz").expect("valid bech32m");
    let decoded = encoded
        .try_from_bech32m("fuzz")
        .expect("expected hrp should match");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bech32m_try_from_bech32m_rejects_mismatched_hrp() {
    let data = b"hello world";
    let encoded = data.try_to_bech32m("fuzz").expect("valid bech32m");
    let err = encoded.try_from_bech32m("other");
    assert!(err.is_err());
}

#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
#[test]
fn dynamic_try_from_bech32m_roundtrip() {
    let data = b"abcd";
    let encoded = data.try_to_bech32m("dyn").expect("valid");
    let dynv = Dynamic::<Vec<u8>>::try_from_bech32m(&encoded, "dyn").expect("decode");
    dynv.with_secret(|d| assert_eq!(d, b"abcd"));
}

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
#[test]
fn dynamic_try_from_bech32_invalid_input_returns_err() {
    assert!(
        secure_gate::Dynamic::<Vec<u8>>::try_from_bech32_unchecked("notabech32string").is_err()
    );
}

#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
#[test]
fn dynamic_try_from_bech32m_invalid_input_returns_err() {
    assert!(Dynamic::<Vec<u8>>::try_from_bech32m_unchecked("notabech32mstring").is_err());
}
