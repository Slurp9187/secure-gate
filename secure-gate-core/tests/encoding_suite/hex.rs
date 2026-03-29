//! encoding_suite/hex.rs — hex encoding/decoding tests

#[cfg(feature = "encoding-hex")]
use secure_gate::{RevealSecret, Fixed, FromHexStr, SecureDecoding, ToHex};
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
use secure_gate::Dynamic;

#[cfg(feature = "encoding-hex")]
#[test]
fn test_slice_to_hex() {
    let input = [0xDEu8, 0xAD, 0xBE, 0xEF];
    assert_eq!(input.to_hex(), "deadbeef");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn slice_to_hex_zeroizing() {
    let encoded = b"hello".to_hex_zeroizing();
    assert_eq!(&*encoded, "68656c6c6f");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_to_hex_zeroizing_matches_plain() {
    let secret = Fixed::new([0x0Au8, 0x0B, 0x0C, 0x0D]);
    let plain = secret.to_hex();
    let zeroizing = secret.to_hex_zeroizing();
    assert_eq!(&*zeroizing, plain.as_str());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_to_hex_upper_zeroizing_matches_plain() {
    let secret = Fixed::new([0x0Au8, 0x0B, 0x0C, 0x0D]);
    let plain = secret.to_hex_upper();
    let zeroizing = secret.to_hex_upper_zeroizing();
    assert_eq!(&*zeroizing, plain.as_str());
}

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
#[test]
fn dynamic_to_hex_zeroizing_matches_plain() {
    let secret: Dynamic<Vec<u8>> = vec![1, 2, 3, 4].into();
    let plain = secret.to_hex();
    let zeroizing = secret.to_hex_zeroizing();
    assert_eq!(&*zeroizing, plain.as_str());
}

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
#[test]
fn dynamic_to_hex_upper_zeroizing_matches_plain() {
    let secret: Dynamic<Vec<u8>> = vec![1, 2, 3, 4].into();
    let plain = secret.to_hex_upper();
    let zeroizing = secret.to_hex_upper_zeroizing();
    assert_eq!(&*zeroizing, plain.as_str());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_to_hex_zeroizing_debug_is_redacted() {
    let secret = Fixed::new([0xDEu8, 0xAD, 0xBE, 0xEF]);
    let encoded = secret.to_hex_zeroizing();
    assert_eq!(format!("{encoded:?}"), "[REDACTED]");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_to_hex_zeroizing_deref_yields_str() {
    let secret = Fixed::new([0xDEu8, 0xAD, 0xBE, 0xEF]);
    let encoded = secret.to_hex_zeroizing();
    assert_eq!(&*encoded, "deadbeef");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_to_hex_zeroizing_all_zeros() {
    let secret = Fixed::new([0u8; 4]);
    let encoded = secret.to_hex_zeroizing();
    assert_eq!(&*encoded, "00000000");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_to_hex_zeroizing_empty() {
    let empty: [u8; 0] = [];
    let encoded = empty.to_hex_zeroizing();
    assert!(encoded.is_empty());
    assert_eq!(&*encoded, "");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_to_hex_zeroizing_single_byte() {
    let secret = Fixed::new([0xFFu8; 1]);
    let encoded = secret.to_hex_zeroizing();
    assert_eq!(&*encoded, "ff");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_roundtrip() {
    let fixed = Fixed::new([1u8; 32]);
    let encoded = fixed.to_hex();
    let decoded = Fixed::<[u8; 32]>::try_from_hex(&encoded).expect("valid hex");
    decoded.with_secret(|d| assert_eq!(d, &[1u8; 32]));
}

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
#[test]
fn dynamic_try_from_hex_roundtrip() {
    let secret: Dynamic<Vec<u8>> = vec![1, 2, 3, 4].into();
    let encoded = secret.to_hex();
    let decoded = Dynamic::<Vec<u8>>::try_from_hex(&encoded).expect("valid hex");
    decoded.with_secret(|d| assert_eq!(d, &[1, 2, 3, 4]));
}

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
#[test]
fn dynamic_try_from_hex_invalid_input_returns_err() {
    assert!(Dynamic::<Vec<u8>>::try_from_hex("not-hex!").is_err());
    assert!(Dynamic::<Vec<u8>>::try_from_hex("xyz").is_err());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn secure_decoding_marker_trait_is_available() {
    fn assert_marker<T: SecureDecoding + ?Sized>(_value: &T) {}
    let input = "00ff";
    assert_marker(input);
    let bytes = input.try_from_hex().expect("hex");
    assert_eq!(bytes, vec![0x00, 0xFF]);
}
