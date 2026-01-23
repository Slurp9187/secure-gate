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

#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
#[test]
fn fixed_deserialize_hex_string() {
    use secure_gate::{ExposeSecret, Fixed};
    // Valid hex string for 4 bytes
    let result: Fixed<[u8; 4]> = serde_json::from_str("\"deadbeef\"").unwrap();
    assert_eq!(result.expose_secret(), &[0xde, 0xad, 0xbe, 0xef]);
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
    assert_eq!(result.expose_secret(), &[1, 2, 3, 4]);
    // Invalid: wrong length
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("\"AQ\""); // 1 byte
    assert!(result.is_err());
}

// #[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
// #[test]
// fn fixed_deserialize_bech32_string() {
//     use secure_gate::{ExposeSecret, Fixed};
//     // Valid bech32 string (hrp "test", data 4 bytes)
//     let hrp_parsed = bech32::Hrp::parse("test").unwrap();
//     let bech32_str = bech32::encode::<bech32::Bech32>(hrp_parsed, &[1, 2, 3, 4]).unwrap();
//     let json_str = format!("\"{}\"", bech32_str);
//     let result: Fixed<[u8; 4]> = serde_json::from_str(&json_str).unwrap();
//     assert_eq!(result.expose_secret(), &[1, 2, 3, 4]);
//     // Invalid: wrong length data
//     let hrp_parsed = bech32::Hrp::parse("test").unwrap();
//     let short_data = bech32::encode::<bech32::Bech32>(hrp_parsed, &[1]).unwrap();
//     let json_short = format!("\"{}\"", short_data);
//     let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str(&json_short);
//     assert!(result.is_err());
// }

// #[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
// #[test]
// fn dynamic_deserialize_hex_string() {
//     use secure_gate::{Dynamic, ExposeSecret};
//     // Valid hex for Vec<u8>
//     let result: Dynamic<Vec<u8>> = serde_json::from_str("\"deadbeef\"").unwrap();
//     assert_eq!(result.expose_secret(), &[0xde, 0xad, 0xbe, 0xef]);
//     // Empty hex
//     let result: Dynamic<Vec<u8>> = serde_json::from_str("\"\"").unwrap();
//     assert_eq!(result.expose_secret().len(), 0);
// }

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
#[test]
fn dynamic_deserialize_base64_string() {
    use secure_gate::{Dynamic, ExposeSecret};
    // Valid base64
    let result: Dynamic<Vec<u8>> = serde_json::from_str("\"AQIDBA\"").unwrap();
    assert_eq!(result.expose_secret(), &[1, 2, 3, 4]);
}

// #[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
// #[test]
// fn dynamic_deserialize_bech32_string() {
//     use secure_gate::{Dynamic, ExposeSecret};
//     // Valid bech32
//     let hrp_parsed = bech32::Hrp::parse("test").unwrap();
//     let bech32_str = bech32::encode::<bech32::Bech32>(hrp_parsed, &[1, 2, 3, 4]).unwrap();
//     let json_str = format!("\"{}\"", bech32_str);
//     let result: Dynamic<Vec<u8>> = serde_json::from_str(&json_str).unwrap();
//     assert_eq!(result.expose_secret(), &[1, 2, 3, 4]);
// }

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
