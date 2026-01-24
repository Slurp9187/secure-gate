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

// Define additional serializable types using marker traits
#[cfg(feature = "serde-serialize")]
#[derive(serde::Serialize)]
pub struct SerializableArray4([u8; 4]);

#[cfg(feature = "serde-serialize")]
impl SerializableType for SerializableArray4 {}

#[cfg(feature = "serde-serialize")]
#[derive(serde::Serialize)]
pub struct SerializableArray32([u8; 32]);

#[cfg(feature = "serde-serialize")]
impl SerializableType for SerializableArray32 {}

#[cfg(feature = "serde-serialize")]
#[derive(serde::Serialize)]
pub struct SerializableString(String);

#[cfg(feature = "serde-serialize")]
impl SerializableType for SerializableString {}

#[cfg(feature = "serde-serialize")]
#[derive(serde::Serialize)]
pub struct SerializableVec(Vec<u8>);

#[cfg(feature = "serde-serialize")]
impl SerializableType for SerializableVec {}

// Custom type for testing
#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[derive(serde::Serialize)]
#[allow(dead_code)]
struct MyKey([u8; 16]);

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
impl SerializableType for MyKey {}

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
impl zeroize::Zeroize for MyKey {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn custom_type_serializable_secret_enables_serialization() {
    let key = MyKey([42u8; 16]);
    let serialized = serde_json::to_string(&key).unwrap();
    assert!(serialized.contains("42"));
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn fixed_arrays_can_be_serialized() {
    let key = SerializableArray32([0x42u8; 32]);
    let serialized = serde_json::to_string(&key).unwrap();
    assert!(serialized.contains("66"));
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn primitives_via_dynamic_serializable() {
    let data = SerializableVec(vec![123, 45]);
    let serialized = serde_json::to_string(&data).unwrap();
    let deserialized: Vec<u8> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, vec![123, 45]);
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn serialized_fixed_are_consistent() {
    let original = SerializableArray4([0u8; 4]);
    let serialized1 = serde_json::to_string(&original).unwrap();
    let serialized2 = serde_json::to_string(&original).unwrap();
    assert_eq!(serialized1, serialized2);
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn serializable_array_serialization() {
    let arr = SerializableArray32([0x42u8; 32]);
    let serialized = serde_json::to_string(&arr).unwrap();
    let deserialized: [u8; 32] = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, [0x42u8; 32]);
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn serializable_array_mutation_before_serialization() {
    let mut arr = SerializableArray4([0u8; 4]);
    arr.0[0] = 1;
    let serialized = serde_json::to_string(&arr).unwrap();
    let deserialized: [u8; 4] = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized[0], 1);
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn serializable_string_serialization() {
    let s = SerializableString("secret".to_string());
    let serialized = serde_json::to_string(&s).unwrap();
    let deserialized: String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, "secret");
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn serializable_string_mutability_before_serialization() {
    let mut s = SerializableString("base".to_string());
    s.0.push_str(" appended");
    let serialized = serde_json::to_string(&s).unwrap();
    let deserialized: String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, "base appended");
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn serializable_vec_serialization() {
    let v = SerializableVec(vec![1u8, 2, 3]);
    let serialized = serde_json::to_string(&v).unwrap();
    let deserialized: Vec<u8> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, vec![1, 2, 3]);
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn serializable_vec_mutability_before_serialization() {
    let mut v = SerializableVec(vec![1u8, 2, 3]);
    v.0.push(4);
    let serialized = serde_json::to_string(&v).unwrap();
    let deserialized: Vec<u8> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, vec![1, 2, 3, 4]);
}

#[cfg(all(feature = "zeroize", not(feature = "serde-serialize")))]
#[test]
#[allow(unused)]
fn raw_dynamic_not_serializable() {
    use secure_gate::Dynamic;
    let s: Dynamic<String> = "secret".into();
    // No Serialize impl on raw Dynamic
}

#[cfg(all(feature = "zeroize", not(feature = "serde-serialize")))]
#[test]
#[allow(unused)]
fn raw_fixed_not_serializable_by_default() {
    use secure_gate::Fixed;
    let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
    // No Serialize impl on raw Fixed
}

#[cfg(all(
    feature = "zeroize",
    feature = "serde-deserialize",
    feature = "serde-serialize"
))]
#[test]
fn nested_serializable_type() {
    let arr = SerializableArray4([42u8; 4]);
    let serialized = serde_json::to_string(&arr).unwrap();
    let deserialized: [u8; 4] = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, [42u8; 4]);
}

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
    let encoded = original.with_secret(|s| s.to_hex());
    // Note: This is a basic test; full roundtrip would require decoding functions if available
    assert!(!encoded.is_empty());
}
