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





#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32string_rejects_valid_bech32_with_disallowed_hrp() {
    // Test valid Bech32 strings from BIP-173 that have HRPs not in our allowed list
    let valid_but_disallowed = [
        "A12UEL5L",  // HRP: "a"
        "a12uel5l",  // HRP: "a" lowercase
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",  // HRP: "an83..."
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",  // HRP: "abcdef1"
    ];

    for s in valid_but_disallowed {
        let err = Bech32String::new(s.to_string()).unwrap_err();
        assert_eq!(err, "invalid bech32 string", "Failed for: {}", s);
    }
}
