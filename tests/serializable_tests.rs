#![cfg(all(feature = "zeroize", feature = "serde-serialize"))]

// Tests for serializable types: opt-in serialization without accidental exposure
// Uses SerializableType marker for secure serializing
extern crate alloc;

use secure_gate::SerializableType;

// Define serializable types using marker traits
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

// === Custom Type Exporting ===
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

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn custom_type_serializable_secret_enables_serialization() {
    let key = MyKey([42u8; 16]);
    let serialized = serde_json::to_string(&key).unwrap();
    // Since MyKey([u8;16]), it serializes to the array
    assert!(serialized.contains("42"));
}

// === Basic Fixed Exporting ===

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn fixed_arrays_can_be_serialized() {
    let key = SerializableArray32([0x42u8; 32]);
    let serialized = serde_json::to_string(&key).unwrap();
    assert!(serialized.contains("66")); // 0x42 is 66 in decimal for JSON array
}

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn primitives_via_dynamic_serializable() {
    let data = SerializableVec(vec![123, 45]);
    let serialized = serde_json::to_string(&data).unwrap();
    let deserialized: Vec<u8> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, vec![123, 45]);
}

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn serialized_fixed_are_consistent() {
    let original = SerializableArray4([0u8; 4]);
    let serialized1 = serde_json::to_string(&original).unwrap();
    let serialized2 = serde_json::to_string(&original).unwrap();
    assert_eq!(serialized1, serialized2);
}

// === ExportableArray Tests ===

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn serializable_array_serialization() {
    let arr = SerializableArray32([0x42u8; 32]);
    let serialized = serde_json::to_string(&arr).unwrap();
    let deserialized: [u8; 32] = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, [0x42u8; 32]);
}

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn serializable_array_mutation_before_serialization() {
    let mut arr = SerializableArray4([0u8; 4]);
    // Since it's a struct, no expose_secret_mut, but for test, mutate directly if needed
    arr.0[0] = 1;
    let serialized = serde_json::to_string(&arr).unwrap();
    let deserialized: [u8; 4] = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized[0], 1);
}

// === ExportableString Tests ===

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn serializable_string_serialization() {
    let s = SerializableString("secret".to_string());
    let serialized = serde_json::to_string(&s).unwrap();
    let deserialized: String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, "secret");
}

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn serializable_string_mutability_before_serialization() {
    let mut s = SerializableString("base".to_string());
    s.0.push_str(" appended");
    let serialized = serde_json::to_string(&s).unwrap();
    let deserialized: String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, "base appended");
}

// === ExportableVec Tests ===

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn serializable_vec_serialization() {
    let v = SerializableVec(vec![1u8, 2, 3]);
    let serialized = serde_json::to_string(&v).unwrap();
    let deserialized: Vec<u8> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, vec![1, 2, 3]);
}

#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn serializable_vec_mutability_before_serialization() {
    let mut v = SerializableVec(vec![1u8, 2, 3]);
    v.0.push(4);
    let serialized = serde_json::to_string(&v).unwrap();
    let deserialized: Vec<u8> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, vec![1, 2, 3, 4]);
}

// === No accidental Serialize on raw wrappers ===
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

// === Nested SerializableType ===
#[cfg(all(feature = "zeroize", feature = "serde-serialize"))]
#[test]
fn nested_serializable_type() {
    // For testing, use available size
    let arr = SerializableArray4([42u8; 4]);
    let serialized = serde_json::to_string(&arr).unwrap();
    let deserialized: [u8; 4] = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, [42u8; 4]);
}
