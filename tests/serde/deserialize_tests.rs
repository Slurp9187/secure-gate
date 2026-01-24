// ==========================================================================
// tests/serde/deserialize_tests.rs
// ==========================================================================
// Serde deserialization integration tests for secure-gate
//
// This file tests deserialization functionality with focus on edge cases and security:
// - Secure deserialization with zeroizing of invalid inputs
// - Validation and bounds checking for encoding types
// - Resource exhaustion resistance

#[cfg(feature = "serde-deserialize")]
#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
#[test]
fn fixed_deserialize_wrong_length() {
    use secure_gate::Fixed;
    // Wrong length: too short
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("[1,2,3]");
    assert!(result.is_err());
    // Wrong length: too long
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("[1,2,3,4,5]");
    assert!(result.is_err());
    // Wrong type: string
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("\"not an array\"");
    assert!(result.is_err());
    // Wrong type: object
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("{\"key\": \"value\"}");
    assert!(result.is_err());
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
#[test]
fn fixed_deserialize_hex_string() {
    use secure_gate::{ExposeSecret, Fixed};
    // Valid hex string for 4 bytes
    let result: Fixed<[u8; 4]> = serde_json::from_str("\"deadbeef\"").unwrap();
    result.with_secret(|r| assert_eq!(r, &[0xde, 0xad, 0xbe, 0xef]));
    // Invalid length: hex for 2 bytes
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("\"dead\"");
    assert!(result.is_err());
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
#[test]
fn fixed_deserialize_base64_string() {
    use secure_gate::{ExposeSecret, Fixed};
    // Valid base64 for 4 bytes: "AQIDBA=="
    let result: Fixed<[u8; 4]> = serde_json::from_str("\"AQIDBA\"").unwrap();
    result.with_secret(|r| assert_eq!(r, &[1, 2, 3, 4]));
    // Invalid: wrong length
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("\"AQ\""); // 1 byte
    assert!(result.is_err());
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
#[test]
fn dynamic_deserialize_base64_string() {
    use secure_gate::{Dynamic, ExposeSecret};
    // Valid base64
    let result: Dynamic<Vec<u8>> = serde_json::from_str("\"AQIDBA\"").unwrap();
    result.with_secret(|r| assert_eq!(r, &[1, 2, 3, 4]));
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn fixed_deserialize_invalid_string() {
    use secure_gate::Fixed;
    // Invalid encoding: not hex/base64/bech32
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("\"invalid\"");
    assert!(result.is_err());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_deserialize_invalid_string() {
    use secure_gate::Dynamic;
    // Invalid encoding
    let result: Result<Dynamic<Vec<u8>>, _> = serde_json::from_str("\"invalid\"");
    assert!(result.is_err());
}
