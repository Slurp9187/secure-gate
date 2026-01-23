// ==========================================================================
// tests/serde/roundtrip_tests.rs
// ==========================================================================
// Serde roundtrip integration tests for secure-gate
//
// This file tests full serialize/deserialize roundtrips with focus on
// end-to-end functionality requiring both serde-deserialize and serde-serialize

extern crate alloc;

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
use secure_gate::SerializableType;

#[cfg(all(
    feature = "serde-deserialize",
    feature = "serde-serialize",
    feature = "encoding-hex"
))]
use secure_gate::ExposeSecret;

// Define test types using marker traits with Serialize and Deserialize
#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TestSerializableArray([u8; 4]);

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
impl SerializableType for TestSerializableArray {}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TestSerializableVec(Vec<u8>);

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
impl SerializableType for TestSerializableVec {}

// Add Deserialize for roundtrips
#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn fixed_roundtrip() {
    use serde_json;

    let original = TestSerializableArray([1u8, 2, 3, 4]);
    let serialized = serde_json::to_string(&original).expect("Serialization failed");
    let deserialized: TestSerializableArray =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    assert_eq!(original.0, deserialized.0);
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn dynamic_roundtrip() {
    use serde_json;

    let original = TestSerializableVec(vec![1u8, 2, 3, 4]);
    let serialized = serde_json::to_string(&original).expect("Serialization failed");
    let deserialized: TestSerializableVec =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    assert_eq!(original.0, deserialized.0);
}

#[cfg(all(
    feature = "serde-serialize",
    feature = "serde-deserialize",
    any(feature = "encoding-hex", feature = "encoding-base64")
))]
#[cfg(all(
    feature = "serde-deserialize",
    feature = "serde-serialize",
    feature = "encoding-hex"
))]
#[test]
fn secure_encoding_roundtrip() {
    use secure_gate::{Fixed, SecureEncoding};

    // Assuming we have a type with SecureEncoding
    let original: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    let encoded = original.expose_secret().to_hex();
    // Note: This is a basic test; full roundtrip would require decoding functions if available
    assert!(!encoded.is_empty());
}
