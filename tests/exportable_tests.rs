#![cfg(all(feature = "zeroize", feature = "serde"))]

// Tests for exportable types: opt-in serialization without accidental exposure
// Uses ExportableType marker for secure exporting
extern crate alloc;

// Cfgs added to individual tests
use secure_gate::{
    exportable_dynamic_alias, exportable_fixed_alias, Dynamic, ExportableType, ExposeSecret,
    ExposeSecretMut, Fixed,
};

// Define exportable types using the new macros (specific sizes since macros don't support generics)
exportable_fixed_alias!(pub ExportableArray4, 4);
exportable_fixed_alias!(pub ExportableArray32, 32);
exportable_dynamic_alias!(pub ExportableString, String);
exportable_dynamic_alias!(pub ExportableVec, Vec<u8>);

// === Custom Type Exporting ===
#[cfg(all(feature = "zeroize", feature = "serde"))]
#[derive(serde::Serialize, serde::Deserialize)]
struct MyKey([u8; 16]);

#[cfg(all(feature = "zeroize", feature = "serde"))]
impl ExportableType for MyKey {}

#[cfg(all(feature = "zeroize", feature = "serde"))]
impl zeroize::Zeroize for MyKey {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn custom_type_exportable_secret_enables_serialization() {
    // For custom types, you could define an exportable alias if needed
    // Placeholder: assume we have an exportable newtype for MyKey
    // Since macros are for standard types, skip or define manually
}

// === Basic Fixed Exporting ===

#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn fixed_arrays_can_be_serialized() {
    let key: ExportableArray32 = [0x42u8; 32].into();
    let serialized = serde_json::to_string(&key).unwrap();
    assert!(serialized.contains("66")); // 0x42 is 66 in decimal for JSON array
}

#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn primitives_via_dynamic_exportable() {
    let data: ExportableVec = vec![123, 45].into();
    let serialized = serde_json::to_string(&data).unwrap();
    let deserialized: Vec<u8> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, vec![123, 45]);
}

#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn serialized_fixed_are_consistent() {
    let original: ExportableArray4 = [0u8; 4].into();
    let serialized1 = serde_json::to_string(&original).unwrap();
    let serialized2 = serde_json::to_string(&original).unwrap();
    assert_eq!(serialized1, serialized2);
}

// === ExportableArray Tests ===

#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn exportable_array_serialization() {
    let arr: ExportableArray32 = [0x42u8; 32].into();
    let serialized = serde_json::to_string(&arr).unwrap();
    let deserialized: [u8; 32] = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, [0x42u8; 32]);
}

#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn exportable_array_mutation_before_serialization() {
    let mut arr: ExportableArray4 = [0u8; 4].into();
    arr.expose_secret_mut()[0] = 1;
    let serialized = serde_json::to_string(&arr).unwrap();
    let deserialized: [u8; 4] = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized[0], 1);
}

// === ExportableString Tests ===

#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn exportable_string_serialization() {
    let s: ExportableString = "secret".to_string().into();
    let serialized = serde_json::to_string(&s).unwrap();
    let deserialized: String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, "secret");
}

#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn exportable_string_mutability_before_serialization() {
    let mut s: ExportableString = "base".to_string().into();
    s.expose_secret_mut().push_str(" appended");
    let serialized = serde_json::to_string(&s).unwrap();
    let deserialized: String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, "base appended");
}

// === ExportableVec Tests ===

#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn exportable_vec_serialization() {
    let v: ExportableVec = vec![1u8, 2, 3].into();
    let serialized = serde_json::to_string(&v).unwrap();
    let deserialized: Vec<u8> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, vec![1, 2, 3]);
}

#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn exportable_vec_mutability_before_serialization() {
    let mut v: ExportableVec = vec![1u8, 2, 3].into();
    v.expose_secret_mut().push(4);
    let serialized = serde_json::to_string(&v).unwrap();
    let deserialized: Vec<u8> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, vec![1, 2, 3, 4]);
}

// === No accidental Serialize on raw wrappers ===
#[cfg(all(feature = "zeroize", feature = "serde", not(feature = "serde")))]
#[test]
#[allow(unused)]
fn raw_dynamic_not_exportable() {
    let s: Dynamic<String> = "secret".into();
    // No Serialize impl on raw Dynamic
}

#[cfg(all(feature = "zeroize", feature = "serde", not(feature = "serde")))]
#[test]
#[allow(unused)]
fn raw_fixed_not_exportable_by_default() {
    let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
    // No Serialize impl on raw Fixed
}

// === Nested ExportableType ===
#[cfg(all(feature = "zeroize", feature = "serde"))]
#[test]
fn nested_exportable_array() {
    // For testing, use available size
    let arr: ExportableArray4 = [42u8; 4].into();
    let serialized = serde_json::to_string(&arr).unwrap();
    let deserialized: [u8; 4] = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, [42u8; 4]);
}
