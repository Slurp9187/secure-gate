#![cfg(feature = "alloc")]

use secure_gate::EncodedSecret;

#[cfg(feature = "encoding-hex")]
use secure_gate::{Fixed, ToHex};

#[cfg(feature = "encoding-hex")]
fn sample_hex_secret() -> EncodedSecret {
    Fixed::new([0xDEu8, 0xAD, 0xBE, 0xEF]).to_hex_zeroizing()
}

#[test]
fn encoded_secret_needs_drop() {
    assert!(core::mem::needs_drop::<EncodedSecret>());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_debug_is_redacted() {
    let encoded = sample_hex_secret();
    assert_eq!(format!("{encoded:?}"), "[REDACTED]");
    assert_eq!(format!("{encoded:#?}"), "[REDACTED]");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_display_shows_content() {
    let encoded = sample_hex_secret();
    assert_eq!(format!("{encoded}"), "deadbeef");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_deref_to_str() {
    let encoded = sample_hex_secret();
    assert_eq!(&*encoded, "deadbeef");
    assert_eq!(encoded.len(), 8);
    assert!(!encoded.is_empty());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_asref_str() {
    let encoded = sample_hex_secret();
    let as_str: &str = encoded.as_ref();
    assert_eq!(as_str, "deadbeef");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_asref_bytes() {
    let encoded = sample_hex_secret();
    let as_bytes: &[u8] = encoded.as_ref();
    assert_eq!(as_bytes, b"deadbeef");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_into_inner_returns_string() {
    let encoded = sample_hex_secret();
    let plain = encoded.into_inner();
    assert_eq!(plain, "deadbeef");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_into_zeroizing_returns_zeroizing() {
    let encoded = sample_hex_secret();
    let protected = encoded.into_zeroizing();
    assert_eq!(&*protected, "deadbeef");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_empty_string() {
    let empty: [u8; 0] = [];
    let encoded = empty.to_hex_zeroizing();

    assert_eq!(format!("{encoded:?}"), "[REDACTED]");
    assert_eq!(format!("{encoded}"), "");
    assert_eq!(&*encoded, "");
    assert!(encoded.is_empty());

    let as_str: &str = encoded.as_ref();
    assert_eq!(as_str, "");

    let encoded = empty.to_hex_zeroizing();
    let as_bytes: &[u8] = encoded.as_ref();
    assert!(as_bytes.is_empty());

    let encoded = empty.to_hex_zeroizing();
    let plain = encoded.into_inner();
    assert_eq!(plain, "");

    let encoded = empty.to_hex_zeroizing();
    let protected = encoded.into_zeroizing();
    assert_eq!(&*protected, "");
}
