// ==========================================================================
// tests/serde/roundtrip_tests.rs
// ==========================================================================
// Serde roundtrip integration tests for secure-gate
//
// This file tests full serialize/deserialize roundtrips with focus on
// end-to-end functionality requiring both serde-deserialize and serde-serialize

use secure_gate::ExposeSecret;

use secure_gate::SerializableSecret;

#[cfg(feature = "serde-serialize")]
impl SerializableSecret for String {}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize", feature = "encoding-hex"))]
#[test]
fn hex_string_serde_roundtrip() {
    use secure_gate::encoding::hex::HexString;
    let original = HexString::new("deadbeef".to_string()).unwrap();
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: HexString = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original.expose_secret(), deserialized.expose_secret());
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize", feature = "encoding-base64"))]
#[test]
fn base64_string_serde_roundtrip() {
    use secure_gate::encoding::base64::Base64String;
    let original = Base64String::new("SGVsbG8gV29ybGQ".to_string()).unwrap(); // "Hello World" base64
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: Base64String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original.expose_secret(), deserialized.expose_secret());
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize", feature = "encoding-bech32"))]
#[test]
fn bech32_string_serde_roundtrip() {
    use secure_gate::encoding::bech32::Bech32String;
    let original = Bech32String::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()).unwrap();
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: Bech32String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original.expose_secret(), deserialized.expose_secret());
}
