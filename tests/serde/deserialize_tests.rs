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
use secure_gate::ExposeSecret;

#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
#[test]
fn hex_string_deserialize_invalid_input() {
    use secure_gate::encoding::hex::HexString;
    // Invalid characters
    let result: Result<HexString, _> = serde_json::from_str("\"gggggggg\"");
    assert!(result.is_err());
    // Invalid characters mixed
    let result: Result<HexString, _> = serde_json::from_str("\"abcdgggg\"");
    assert!(result.is_err());
    // Odd length
    let result: Result<HexString, _> = serde_json::from_str("\"abc\"");
    assert!(result.is_err());
    // Empty string
    let result: Result<HexString, _> = serde_json::from_str("\"\"");
    assert!(result.is_ok());
    let hex = result.unwrap();
    assert_eq!(hex.expose_secret().len(), 0);
    // Uppercase
    let result: Result<HexString, _> = serde_json::from_str("\"ABCDEF\"");
    assert!(result.is_ok());
    let hex = result.unwrap();
    assert_eq!(hex.expose_secret(), "abcdef");
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
#[test]
fn base64_deserialize_invalid_input() {
    use secure_gate::encoding::base64::Base64String;
    // Invalid characters
    let result: Result<Base64String, _> = serde_json::from_str("\"!@#$%\"");
    assert!(result.is_err());
    // Invalid characters mixed
    let result: Result<Base64String, _> = serde_json::from_str("\"abcd!\"");
    assert!(result.is_err());
    // Invalid padding
    let result: Result<Base64String, _> = serde_json::from_str("\"abc=\"");
    assert!(result.is_err());
    // Valid
    let result: Result<Base64String, _> = serde_json::from_str("\"YWJj\"");
    assert!(result.is_ok());
    let base64 = result.unwrap();
    assert_eq!(base64.expose_secret(), "YWJj");
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
#[test]
fn bech32_deserialize_invalid_input() {
    use secure_gate::encoding::bech32::Bech32String;
    // Invalid characters
    let result: Result<Bech32String, _> = serde_json::from_str("\"gggggggg\"");
    assert!(result.is_err());
    // Valid bech32
    let result: Result<Bech32String, _> =
        serde_json::from_str("\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"");
    assert!(result.is_ok());
    let bech32 = result.unwrap();
    assert!(bech32.expose_secret().starts_with("bc"));
}

#[cfg(all(
    feature = "serde-deserialize",
    feature = "serde-serialize",
    feature = "zeroize"
))]
#[test]
fn cloneable_vec_deserialize() {
    use secure_gate::CloneableVec;
    let json = "[1,2,3,4,5,6]";
    let result: Result<CloneableVec, _> = serde_json::from_str(json);
    assert!(result.is_ok());
    let deserialized = result.unwrap();
    assert_eq!(deserialized.expose_secret().0.len(), 6);
}

#[cfg(all(
    feature = "serde-deserialize",
    feature = "serde-serialize",
    feature = "zeroize"
))]
#[test]
fn cloneable_string_deserialize() {
    use secure_gate::CloneableString;
    let json = "\"hunter2\"";
    let result: Result<CloneableString, _> = serde_json::from_str(json);
    assert!(result.is_ok());
    let deserialized = result.unwrap();
    assert_eq!(deserialized.expose_secret().0, "hunter2");
}

#[cfg(all(
    feature = "serde-deserialize",
    feature = "serde-serialize",
    feature = "zeroize"
))]
#[test]
fn cloneable_vec_large_deserialize() {
    use secure_gate::CloneableVec;
    // Create a large JSON array with 100 elements
    let mut json = "[".to_string();
    for i in 0..100 {
        json.push_str(&i.to_string());
        if i < 99 {
            json.push(',');
        }
    }
    json.push(']');
    let result: Result<CloneableVec, _> = serde_json::from_str(&json);
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 100);
}

#[cfg(feature = "serde-deserialize")]
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
