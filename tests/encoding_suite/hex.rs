//! encoding_suite/hex.rs — hex encoding/decoding tests

#[cfg(feature = "encoding-hex")]
use secure_gate::{ExposeSecret, Fixed, FromHexStr, SecureDecoding, ToHex};
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

#[cfg(feature = "encoding-hex")]
#[test]
fn secure_decoding_marker_trait_is_available() {
    fn assert_marker<T: SecureDecoding + ?Sized>(_value: &T) {}
    let input = "00ff";
    assert_marker(input);
    let bytes = input.try_from_hex().expect("hex");
    assert_eq!(bytes, vec![0x00, 0xFF]);
}
