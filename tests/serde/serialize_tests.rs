// ==========================================================================
// tests/serde/serialize_tests.rs
// ==========================================================================
// Serde serialization integration tests for secure-gate
//
// This file tests serialization functionality with focus on edge cases and security:
// - Opt-in serialization via SerializableSecret
// - Validation and roundtrips for encoding types
// - Prevention of accidental exfiltration

use secure_gate::SerializableSecret;

#[cfg(all(feature = "serde-serialize", feature = "rand"))]
#[test]
fn fixed_random_serialize() {
    use secure_gate::{SerializableSecret, random::FixedRandom};
    use serde::Serialize;

    struct TestFixedRandom(FixedRandom<32>);

    impl SerializableSecret for TestFixedRandom {}

    impl Serialize for TestFixedRandom {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.0.serialize(serializer)
        }
    }

    let random: FixedRandom<32> = FixedRandom::generate();
    let test_random = TestFixedRandom(random);
    let serialized = serde_json::to_string(&test_random).unwrap();
    // Deserialize not supported for random types - only test serialization
    assert!(!serialized.is_empty());
    // Ensure serialized contains valid JSON (bytes as array)
    assert!(serialized.starts_with('['));
    assert!(serialized.ends_with(']'));
}

#[cfg(all(feature = "serde-serialize", feature = "rand"))]
#[test]
fn dynamic_random_serialize() {
    use secure_gate::{SerializableSecret, random::DynamicRandom};
    use serde::Serialize;

    struct TestDynamicRandom(DynamicRandom);

    impl SerializableSecret for TestDynamicRandom {}

    impl Serialize for TestDynamicRandom {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.0.serialize(serializer)
        }
    }

    let random: DynamicRandom = DynamicRandom::generate(64);
    let test_random = TestDynamicRandom(random);
    let serialized = serde_json::to_string(&test_random).unwrap();
    assert!(!serialized.is_empty());
    // Should be byte array
    assert!(serialized.starts_with('['));
    assert!(serialized.ends_with(']'));
}

#[cfg(feature = "serde-serialize")]
#[test]
fn no_accidental_serialization_without_marker() {
    // This test demonstrates that types without SerializableSecret cannot be serialized
    // Fixed<u8> cannot be serialized because u8 doesn't impl SerializableSecret
    // We can't write a runtime test for this since it's a compile error, but this serves as documentation
    use secure_gate::Fixed;
    let _secret = Fixed::new(42u8);
    // serde_json::to_string(&_secret); // This would fail to compile if attempted
}
