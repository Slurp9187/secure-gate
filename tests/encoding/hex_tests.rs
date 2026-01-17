// ==========================================================================
// tests/encoding_hex_tests.rs
// ==========================================================================
// Tests for hex encoding.

#![cfg(test)]

#[cfg(feature = "encoding-hex")]
#[allow(unused_imports)] // Clippy may not recognize use in macro
use secure_gate::{fixed_alias_random, ExposeSecret, HexString};

use hex;

#[cfg(feature = "encoding-hex")]
#[cfg(feature = "rand")]
#[test]
fn into_hex_via_alias() {
    fixed_alias_random!(HexKey, 32);

    let hex = HexKey::generate().into_hex();

    assert_eq!(hex.expose_secret().len(), 64);
    assert!(hex
        .expose_secret()
        .chars()
        .all(|c: char| c.is_ascii_hexdigit()));
    assert!(hex.expose_secret().chars().all(|c: char| !c.is_uppercase()));

    let bytes = hex.decode_into_bytes();
    assert_eq!(bytes.len(), 32);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_new_rejects_invalid() {
    let s = "invalid hex".to_string(); // odd length
    let err = HexString::new(s).unwrap_err();
    assert_eq!(err, "invalid hex string");

    let s = "g".to_string(); // invalid digit
    let err = HexString::new(s).unwrap_err();
    assert_eq!(err, "invalid hex string");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_new_in_place_lowercase() {
    let s = "DEADBEEF".to_string();
    let hex = HexString::new(s).unwrap();
    assert_eq!(hex.expose_secret(), "deadbeef");
    assert_eq!(hex.byte_len(), 4);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_valid_parsing() {
    let s = "deadbeef".to_string();
    let hex = HexString::new(s).unwrap();
    assert_eq!(hex.expose_secret(), "deadbeef");
    assert_eq!(hex.byte_len(), 4);

    let bytes = hex.decode_into_bytes();
    assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_empty() {
    let hex = HexString::new("".to_string()).unwrap();
    assert_eq!(hex.expose_secret(), "");
    assert_eq!(hex.byte_len(), 0);
    assert_eq!(hex.decode_into_bytes(), Vec::<u8>::new());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_odd_length_fails() {
    let err = HexString::new("abc".to_string()).unwrap_err();
    assert_eq!(err, "invalid hex string");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_rejects_more_invalid_chars() {
    // Test invalid characters beyond 'g'
    let s = "dead!".to_string(); // '!' invalid
    let err = HexString::new(s).unwrap_err();
    assert_eq!(err, "invalid hex string");

    let s = "beef@".to_string(); // '@' invalid
    let err = HexString::new(s).unwrap_err();
    assert_eq!(err, "invalid hex string");

    let s = "cafe\n".to_string(); // newline invalid
    let err = HexString::new(s).unwrap_err();
    assert_eq!(err, "invalid hex string");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_byte_len_longer() {
    // Test byte_len for a longer string
    let s = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(); // 64 chars
    let hex = HexString::new(s).unwrap();
    assert_eq!(hex.byte_len(), 32);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_very_long_string() {
    // 1024 bytes → 2048 hex chars
    let long_bytes = vec![0xABu8; 1024];
    let hex_str = hex::encode(&long_bytes);
    let hex = HexString::new(hex_str).unwrap();
    assert_eq!(hex.byte_len(), 1024);
    assert_eq!(hex.len(), 2048);
    assert_eq!(hex.decode_into_bytes(), long_bytes);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_round_trip() {
    // Test that decoding and re-encoding matches
    let original_bytes = vec![0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x00];
    let hex_str = hex::encode(&original_bytes);
    let hex = HexString::new(hex_str).unwrap();
    let decoded = hex.decode_into_bytes();
    assert_eq!(decoded, original_bytes);
}

#[cfg(all(feature = "encoding-hex", feature = "ct-eq"))]
#[test]
fn hexstring_constant_time_eq() {
    let s1 = "deadbeef".to_string();
    let s2 = "deadbeef".to_string();
    let hex1 = HexString::new(s1).unwrap();
    let hex2 = HexString::new(s2).unwrap();
    assert_eq!(hex1, hex2);

    // Test unequal
    let s3 = "beefdead".to_string();
    let hex3 = HexString::new(s3).unwrap();
    assert_ne!(hex1, hex3);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_decode_borrowing() {
    let hex = HexString::new("deadbeef".to_string()).unwrap();
    let bytes = hex.decode_to_bytes();
    assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    // Verify hex is still usable (borrowing)
    let bytes2 = hex.decode_to_bytes();
    assert_eq!(bytes2, bytes);
}

#[cfg(all(feature = "encoding-hex", feature = "rand"))]
#[test]
fn rng_hex_integration() {
    use secure_gate::random::FixedRandom;
    let rng = FixedRandom::<32>::generate();
    let hex = rng.into_hex();
    assert_eq!(hex.decode_into_bytes().len(), 32);
}
