//! encoding_suite/hex.rs — hex encoding/decoding tests

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
use secure_gate::Dynamic;
#[cfg(feature = "encoding-hex")]
use secure_gate::{Fixed, FromHexStr, RevealSecret, SecureDecoding, SecureEncoding, ToHex};

#[cfg(feature = "encoding-hex")]
#[test]
fn test_slice_to_hex() {
    let input = [0xDEu8, 0xAD, 0xBE, 0xEF];
    assert_eq!(input.to_hex().into_inner(), "deadbeef");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_roundtrip() {
    let fixed = Fixed::new([1u8; 32]);
    let encoded = fixed.to_hex().into_inner();
    let decoded = Fixed::<[u8; 32]>::try_from_hex(&encoded).expect("valid hex");
    decoded.with_secret(|d| assert_eq!(d, &[1u8; 32]));
}

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
#[test]
fn dynamic_try_from_hex_roundtrip() {
    let secret: Dynamic<Vec<u8>> = vec![1, 2, 3, 4].into();
    let encoded = secret.to_hex().into_inner();
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
fn str_receiver_try_from_hex_decodes_via_blanket_impl() {
    let input = "00ff";
    let bytes = input.try_from_hex().expect("hex");
    assert_eq!(bytes, vec![0x00, 0xFF]);
}

/// Existence pin for the two marker traits this branch still carries.
///
/// `main` removed `SecureEncoding` / `SecureDecoding` in 44232a8 and deleted this pin
/// with them; 0.8 kept the traits, so the pin has to stay too. They are public, are
/// re-exported at the crate root, and are the only items of their kind unique to this
/// branch — an empty marker with no methods still needs a compile pin.
///
/// Deliberately alloc-free so it runs in every `encoding-*` row, not just the alloc ones.
#[cfg(feature = "encoding-hex")]
#[test]
fn secure_encoding_and_decoding_markers_are_available() {
    fn assert_decoding<T: SecureDecoding + ?Sized>(_value: &T) {}
    fn assert_encoding<T: SecureEncoding + ?Sized>(_value: &T) {}

    // `SecureDecoding` is blanket-implemented for `AsRef<str>`, `SecureEncoding` for
    // `AsRef<[u8]>`. Neither gates the `From*Str` / `To*` blankets — see their rustdoc.
    assert_decoding("00ff");
    assert_encoding(&[0x00u8, 0xFF]);
}

// No-alloc decode path tests: Fixed::try_from_hex works with only encoding-hex (no alloc feature)
#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_mixed_case() {
    let result = Fixed::<[u8; 4]>::try_from_hex("AAbbCCdd");
    assert!(result.is_ok());
    result
        .unwrap()
        .with_secret(|b| assert_eq!(b, &[0xAA, 0xBB, 0xCC, 0xDD]));
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_wrong_length_too_long() {
    // 5 bytes encoded → 4-byte Fixed
    assert!(Fixed::<[u8; 4]>::try_from_hex("aabbccddee").is_err());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_wrong_length_too_short() {
    // 3 bytes encoded → 4-byte Fixed
    assert!(Fixed::<[u8; 4]>::try_from_hex("aabbcc").is_err());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_invalid_chars() {
    assert!(Fixed::<[u8; 4]>::try_from_hex("xxyyzz00").is_err());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_all_zeros() {
    let result = Fixed::<[u8; 4]>::try_from_hex("00000000");
    assert!(result.is_ok());
    result.unwrap().with_secret(|b| assert_eq!(b, &[0u8; 4]));
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_empty_input() {
    assert!(Fixed::<[u8; 4]>::try_from_hex("").is_err());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_single_byte() {
    let result = Fixed::<[u8; 1]>::try_from_hex("ff");
    assert!(result.is_ok());
    result.unwrap().with_secret(|b| assert_eq!(b, &[0xFF]));
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_odd_length() {
    // Odd-length hex is invalid (not a whole number of bytes)
    assert!(Fixed::<[u8; 2]>::try_from_hex("abc").is_err());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn fixed_try_from_hex_large_n() {
    let data = [0x42u8; 128];
    let hex: String = data.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        write!(acc, "{b:02x}").unwrap();
        acc
    });
    let result = Fixed::<[u8; 128]>::try_from_hex(&hex);
    assert!(result.is_ok());
    result
        .unwrap()
        .with_secret(|b| assert_eq!(b, &[0x42u8; 128]));
}
