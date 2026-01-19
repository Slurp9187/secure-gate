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
