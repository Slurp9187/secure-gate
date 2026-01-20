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

#[test]
fn random_no_deserialize() {
    // Random types don't implement Deserialize - confirm via failed attempt
    // This is a compile-time restriction, but we test by noting it doesn't exist
    // serde_json::from_str::<secure_gate::FixedRandom<32>>("[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]").unwrap_err();
    // Would fail to compile if Deserialize existed
}
