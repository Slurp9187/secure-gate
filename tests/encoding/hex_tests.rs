// ==========================================================================
// tests/encoding_hex_tests.rs
// ==========================================================================
// Tests for hex encoding.

#![cfg(test)]

#[cfg(feature = "encoding-hex")]
use secure_gate::{fixed_alias_rng, HexString};

#[cfg(feature = "encoding-hex")]
#[cfg(feature = "rand")]
#[test]
fn into_hex_via_alias() {
    fixed_alias_rng!(HexKey, 32);

    let hex = HexKey::generate().into_hex();

    assert_eq!(hex.expose_secret().len(), 64);
    assert!(hex
        .expose_secret()
        .chars()
        .all(|c: char| c.is_ascii_hexdigit()));
    assert!(hex.expose_secret().chars().all(|c: char| !c.is_uppercase()));

    let bytes = hex.to_bytes();
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

    let bytes = hex.to_bytes();
    assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_empty() {
    let hex = HexString::new("".to_string()).unwrap();
    assert_eq!(hex.expose_secret(), "");
    assert_eq!(hex.byte_len(), 0);
    assert_eq!(hex.to_bytes(), Vec::<u8>::new());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_odd_length_fails() {
    let err = HexString::new("abc".to_string()).unwrap_err();
    assert_eq!(err, "invalid hex string");
}
