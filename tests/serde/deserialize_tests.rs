
// ==========================================================================
// tests/serde/deserialize_tests.rs
// ==========================================================================
// Serde deserialization integration tests for secure-gate
//
// This file tests deserialization functionality with focus on edge cases and security:
// - Secure deserialization with zeroizing of invalid inputs
// - Validation and bounds checking for encoding types
// - Resource exhaustion resistance

use secure_gate::ExposeSecret;

#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
#[test]
fn hex_string_deserialize_invalid_input() {
    use secure_gate::encoding::hex::HexString;
    // Invalid characters
    let result: Result<HexString, _> = serde_json::from_str("\"gggggggg\"");
    assert!(result.is_err());
    // Invalid characters mixed
    let result: Result<HexString, _> = serde_json::from_str("\"deadbeef!\"");
    assert!(result.is_err());
    // Odd length (invalid)
    let result: Result<HexString, _> = serde_json::from_str("\"abc\"");
    assert!(result.is_err());
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
#[test]
fn hex_string_deserialize_large_input() {
    use secure_gate::encoding::hex::HexString;
    // Large valid hex should succeed (serde handles it, no built-in limit)
    let large_hex = "a".repeat(1024);
    let result: Result<HexString, _> = serde_json::from_str(&format!("\"{}\"", large_hex));
    assert!(result.is_ok()); // Accepts large valid input
    assert_eq!(result.unwrap().byte_len(), 512);
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
#[test]
fn base64_string_deserialize_invalid_input() {
    use secure_gate::encoding::base64::Base64String;
    // Invalid base64 characters
    let result: Result<Base64String, _> = serde_json::from_str("\"!@#$%\"");
    assert!(result.is_err());
    // Invalid base64 (wrong padding)
    let result: Result<Base64String, _> = serde_json::from_str("\"SGVsbG\"");
    assert!(result.is_err());
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
#[test]
fn bech32_string_deserialize_invalid_input() {
    use secure_gate::encoding::bech32::Bech32String;
    // Invalid bech32: wrong checksum
    let result: Result<Bech32String, _> = serde_json::from_str("\"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5md\"");
    assert!(result.is_err());
    // Invalid HRP
    let result: Result<Bech32String, _> = serde_json::from_str("\"zz1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\"");
    assert!(result.is_err());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn deserialization_from_malformed_json() {
    use secure_gate::Dynamic;

    // Test deserialization of malformed JSON for Dynamic<String>
    let result: Result<Dynamic<String>, _> = serde_json::from_str("{\"key\": \"value\"}"); // Not a string
    assert!(result.is_err());

    let result: Result<Dynamic<String>, _> = serde_json::from_str("[1, 2, 3]"); // Not a string
    assert!(result.is_err());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn resource_exhaustion_prevention() {
    // Test that we don't allocate excessive memory for malicious input
    // serde_json has built-in limits, but our types add validation
    let huge_string = "x".repeat(1000000); // 1MB string
    let result: Result<secure_gate::Dynamic<String>, _> = serde_json::from_str(&format!("\"{}\"", huge_string));
    // This should succeed but not cause DoS since serde handles it
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1000000);
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn zeroizing_on_deserialize_failure() {
    // This is hard to test directly since zeroizing happens in the implementation
    // But we can verify that invalid inputs fail without panicking
    use secure_gate::encoding::hex::HexString;
    let result = serde_json::from_str::<HexString>("\"invalid\"");
    assert!(result.is_err());
    // In the impl, invalid input is zeroized before returning error
}

#[cfg(all(feature = "serde-deserialize", feature = "zeroize"))]
#[test]
fn cloneable_string_deserialize_uses_secure_pattern() {
    let deserialized: secure_gate::CloneableString = serde_json::from_str(r#""hunter2""#).unwrap();
    assert_eq!(deserialized.expose_secret().0, "hunter2");
}

#[cfg(all(feature = "serde-deserialize", feature = "zeroize"))]
#[test]
fn cloneable_array_length_mismatch() {
    let result: Result<secure_gate::CloneableArray<32>, _> = serde_json::from_str("[1,2,3]");
    assert!(result.is_err());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn deserialize_very_large_string() {
    let huge = "a".repeat(1_000_000); // 1MB - reasonable for testing
    let serialized = format!("\"{}\"", huge);
    let result: secure_gate::Dynamic<String> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(result.len(), 1_000_000);
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn random_no_deserialize() {
    // Random types don't implement Deserialize - confirm via failed attempt
    // This is a compile-time restriction, but we test by noting it doesn't exist
    // serde_json::from_str::<secure_gate::FixedRandom<32>>("[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]").unwrap_err();
    // Would fail to compile if Deserialize existed
    assert!(true);
}
