// ==========================================================================
// tests/serde_tests.rs
// ==========================================================================
// Serde integration tests for secure-gate

#[cfg(feature = "serde")]
#[test]
fn cloneable_vec_serde_roundtrip() {
    use secure_gate::CloneableVec;
    let original: CloneableVec = vec![1u8, 2, 3, 4].into();
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: CloneableVec = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original.expose_secret().0, deserialized.expose_secret().0);
}

#[cfg(feature = "serde")]
#[test]
fn cloneable_string_serde_roundtrip() {
    use secure_gate::CloneableString;
    let original: CloneableString = "secret".to_string().into();
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: CloneableString = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original.expose_secret().0, deserialized.expose_secret().0);
}

#[cfg(feature = "serde")]
#[test]
fn hex_string_serde_roundtrip() {
    use secure_gate::encoding::hex::HexString;
    let original = HexString::new("deadbeef".to_string()).unwrap();
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: HexString = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original.expose_secret(), deserialized.expose_secret());
}

#[cfg(feature = "serde")]
#[test]
fn fixed_random_serialize() {
    use secure_gate::random::FixedRandom;
    let random: FixedRandom<32> = FixedRandom::generate();
    let serialized = serde_json::to_string(&random).unwrap();
    // Deserialize not supported for random types - only test serialization
    assert!(serialized.len() > 0);
}
#[test]
fn dummy() {
    assert!(true);
}
