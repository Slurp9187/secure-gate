// ==========================================================================
// tests/encoding/bech32_tests.rs
// ==========================================================================
// Tests for bech32 encoding.

#![cfg(test)]

use secure_gate::encoding::bech32::Bech32String;

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32string_new_rejects_invalid() {
    // Invalid HRP
    let s = "invalid1data".to_string();
    let err = Bech32String::new(s).unwrap_err();
    assert_eq!(err, "invalid bech32 string");

    // Invalid bech32
    let s = "age_invalid".to_string();
    let err = Bech32String::new(s).unwrap_err();
    assert_eq!(err, "invalid bech32 string");

    // Invalid characters
    let s = "age!invalid".to_string();
    let err = Bech32String::new(s).unwrap_err();
    assert_eq!(err, "invalid bech32 string");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32string_empty_fails() {
    let err = Bech32String::new("".to_string()).unwrap_err();
    assert_eq!(err, "invalid bech32 string");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32string_rejects_invalid_hrp() {
    // HRP not in allowed list, but valid bech32
    // Since it's valid bech32 but wrong HRP, it should fail
    let s = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(); // bitcoin
    let err = Bech32String::new(s).unwrap_err();
    assert_eq!(err, "invalid bech32 string");
}
