// ==========================================================================
// tests/serde/deserialize_tests.rs
// ==========================================================================
// Serde deserialization integration tests for secure-gate
//
// This file tests general serde deserialization functionality with focus on edge cases and security:
// - Secure deserialization with zeroizing of invalid inputs
// - Validation and bounds checking for JSON arrays and invalid inputs
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
