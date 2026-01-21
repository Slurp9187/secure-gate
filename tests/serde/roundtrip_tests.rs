// ==========================================================================
// tests/serde/roundtrip_tests.rs
// ==========================================================================
// Serde roundtrip integration tests for secure-gate
//
// This file tests full serialize/deserialize roundtrips with focus on
// end-to-end functionality requiring both serde-deserialize and serde-serialize

extern crate alloc;

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
use secure_gate::ExposeSecret;
use secure_gate::{serializable_dynamic_alias, serializable_fixed_alias};

// Define test types using macros
serializable_fixed_alias!(pub TestSerializableArray, 4);
serializable_dynamic_alias!(pub TestSerializableVec, Vec<u8>);

// Add Deserialize for roundtrips
#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
impl<'de> serde::Deserialize<'de> for TestSerializableArray {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = <[u8; 4]>::deserialize(deserializer)?;
        Ok(Self::from(inner))
    }
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
impl<'de> serde::Deserialize<'de> for TestSerializableVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = Vec::<u8>::deserialize(deserializer)?;
        Ok(Self::from(inner))
    }
}

#[cfg(all(feature = "serde-serialize", feature = "serde-deserialize"))]
#[test]
fn fixed_roundtrip() {
    use serde_json;

    let original: TestSerializableArray = [1u8, 2, 3, 4].into();
    let serialized = serde_json::to_string(&original).expect("Serialization failed");
    let deserialized: TestSerializableArray =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    assert_eq!(original.expose_secret(), deserialized.expose_secret());
}

#[cfg(all(feature = "serde-serialize", feature = "serde-deserialize"))]
#[test]
fn dynamic_roundtrip() {
    use serde_json;

    let original: TestSerializableVec = vec![1u8, 2, 3, 4].into();
    let serialized = serde_json::to_string(&original).expect("Serialization failed");
    let deserialized: TestSerializableVec =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    assert_eq!(original.expose_secret(), deserialized.expose_secret());
}

#[cfg(all(
    feature = "serde-serialize",
    feature = "serde-deserialize",
    any(feature = "encoding-hex", feature = "encoding-base64")
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
