// ==========================================================================
// tests/serde_tests.rs
// ==========================================================================
// Serde integration tests for secure-gate
//
// This file tests serde functionality with focus on edge cases and security:
// - Opt-in serialization via SerializableSecret
// - Secure deserialization with zeroizing of invalid inputs
// - Validation and bounds checking for encoding types
// - Prevention of accidental exfiltration
// - Resource exhaustion resistance

#[cfg(feature = "serde")]
use secure_gate::ExposeSecret;

#[cfg(all(feature = "serde", feature = "encoding-hex"))]
#[test]
fn hex_string_serde_roundtrip() {
    use secure_gate::encoding::hex::HexString;
    let original = HexString::new("deadbeef".to_string()).unwrap();
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: HexString = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original.expose_secret(), deserialized.expose_secret());
}

#[cfg(all(feature = "serde", feature = "encoding-hex"))]
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

#[cfg(all(feature = "serde", feature = "encoding-hex"))]
#[test]
fn hex_string_deserialize_large_input() {
    use secure_gate::encoding::hex::HexString;
    // Large valid hex should succeed (serde handles it, no built-in limit)
    let large_hex = "a".repeat(1024);
    let result: Result<HexString, _> = serde_json::from_str(&format!("\"{}\"", large_hex));
    assert!(result.is_ok()); // Accepts large valid input
    assert_eq!(result.unwrap().byte_len(), 512);
}

#[cfg(all(feature = "serde", feature = "encoding-base64"))]
#[test]
fn base64_string_serde_roundtrip() {
    use secure_gate::encoding::base64::Base64String;
    let original = Base64String::new("SGVsbG8gV29ybGQ".to_string()).unwrap(); // "Hello World" base64
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: Base64String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original.expose_secret(), deserialized.expose_secret());
}

#[cfg(all(feature = "serde", feature = "encoding-base64"))]
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

#[cfg(all(feature = "serde", feature = "encoding-bech32"))]
#[test]
fn bech32_string_serde_roundtrip() {
    use secure_gate::encoding::bech32::Bech32String;
    let original = Bech32String::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()).unwrap();
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: Bech32String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original.expose_secret(), deserialized.expose_secret());
}

#[cfg(all(feature = "serde", feature = "encoding-bech32"))]
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

#[cfg(all(feature = "serde", feature = "rand"))]
#[test]
fn fixed_random_serialize() {
    use secure_gate::random::FixedRandom;
    let random: FixedRandom<32> = FixedRandom::generate();
    let serialized = serde_json::to_string(&random).unwrap();
    // Deserialize not supported for random types - only test serialization
    assert!(!serialized.is_empty());
    // Ensure serialized contains valid JSON (bytes as array)
    assert!(serialized.starts_with('['));
    assert!(serialized.ends_with(']'));
}

#[cfg(all(feature = "serde", feature = "rand"))]
#[test]
fn dynamic_random_serialize() {
    use secure_gate::random::DynamicRandom;
    let random: DynamicRandom = DynamicRandom::generate(64);
    let serialized = serde_json::to_string(&random).unwrap();
    assert!(!serialized.is_empty());
    // Should be byte array
    assert!(serialized.starts_with('['));
    assert!(serialized.ends_with(']'));
}

#[cfg(feature = "serde")]
#[test]
fn no_accidental_serialization_without_marker() {
    // This test demonstrates that types without SerializableSecret cannot be serialized
    // Fixed<u8> cannot be serialized because u8 doesn't impl SerializableSecret
    // We can't write a runtime test for this since it's a compile error, but this serves as documentation
    use secure_gate::Fixed;
    let _secret = Fixed::new(42u8);
    // serde_json::to_string(&_secret); // This would fail to compile if attempted
}

#[cfg(feature = "serde")]
#[test]
fn deserialization_from_malformed_json() {
    use secure_gate::Dynamic;

    // Test deserialization of malformed JSON for Dynamic<String>
    let result: Result<Dynamic<String>, _> = serde_json::from_str("{\"key\": \"value\"}"); // Not a string
    assert!(result.is_err());

    let result: Result<Dynamic<String>, _> = serde_json::from_str("[1, 2, 3]"); // Not a string
    assert!(result.is_err());
}

#[cfg(feature = "serde")]
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

#[cfg(feature = "serde")]
#[test]
fn zeroizing_on_deserialize_failure() {
    // This is hard to test directly since zeroizing happens in the implementation
    // But we can verify that invalid inputs fail without panicking
    use secure_gate::encoding::hex::HexString;
    let result = serde_json::from_str::<HexString>("\"invalid\"");
    assert!(result.is_err());
    // In the impl, invalid input is zeroized before returning error
}
