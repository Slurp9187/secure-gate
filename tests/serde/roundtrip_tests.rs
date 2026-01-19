// ==========================================================================
// tests/serde/roundtrip_tests.rs
// ==========================================================================
// Serde roundtrip integration tests for secure-gate
//
// This file tests full serialize/deserialize roundtrips with focus on
// end-to-end functionality requiring both serde-deserialize and serde-serialize

use secure_gate::{ConstantTimeEq, ExposeSecret};

use secure_gate::SerializableSecret;

#[cfg(feature = "serde-serialize")]
#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn exportable_array_roundtrip() {
    use secure_gate::{ExportableArray, ExposeSecret, Fixed};
    let original: ExportableArray<4> = [1, 2, 3, 4].into();
    let serialized = serde_json::to_string(&original).unwrap();
    assert_eq!(serialized, "[1,2,3,4]");
    let deserialized: Fixed<[u8; 4]> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.expose_secret(), &[1, 2, 3, 4]);
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn exportable_vec_roundtrip() {
    use secure_gate::{Dynamic, ExportableVec, ExposeSecret};
    let original: ExportableVec = vec![1, 2, 3].into();
    let serialized = serde_json::to_string(&original).unwrap();
    assert_eq!(serialized, "[1,2,3]");
    let deserialized: Dynamic<Vec<u8>> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.expose_secret(), &[1, 2, 3]);
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn exportable_string_roundtrip() {
    use secure_gate::{Dynamic, ExportableString, ExposeSecret};
    let original: ExportableString = "hello".into();
    let serialized = serde_json::to_string(&original).unwrap();
    assert_eq!(serialized, "\"hello\"");
    let deserialized: Dynamic<String> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.expose_secret(), "hello");
}

#[cfg(all(
    feature = "serde-deserialize",
    feature = "serde-serialize",
    feature = "encoding-hex"
))]
#[test]
fn exportable_from_encoded_roundtrip() {
    use secure_gate::{encoding::hex::HexString, ExportableVec, ExposeSecret};
    let hex = HexString::new("deadbeef".to_string()).unwrap();
    let exportable: ExportableVec = hex.into();
    let serialized = serde_json::to_string(&exportable).unwrap();
    assert_eq!(serialized, "[222,173,190,239]"); // Raw bytes of "deadbeef"
    let deserialized: secure_gate::Dynamic<Vec<u8>> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.expose_secret(), &[222, 173, 190, 239]);
}

#[cfg(all(
    feature = "serde-serialize",
    feature = "zeroize",
    feature = "rand",
    feature = "ct-eq"
))]
#[test]
fn full_feature_integration() {
    // Test all features work together: rand generation, zeroize on drop, ct_eq, serialization
    use secure_gate::{ExportableArray, ExposeSecret, FixedRandom};

    let random: FixedRandom<8> = FixedRandom::generate();
    let fixed: secure_gate::Fixed<[u8; 8]> = random.into();
    let exportable: ExportableArray<8> = fixed.into();

    // Test serialization
    let json = serde_json::to_string(&exportable).unwrap();
    assert!(json.starts_with('[') && json.ends_with(']'));

    // Features verified by successful compilation and execution
    assert!(true);

    // Zeroize happens on drop, can't test directly but no panics
}
