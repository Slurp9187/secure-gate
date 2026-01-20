// ==========================================================================
// tests/serde/serialize_tests.rs
// ==========================================================================
// Serde serialization integration tests for secure-gate
//
// This file tests serialization functionality with focus on edge cases and security:
// - Opt-in serialization via ExportableType
// - Validation and roundtrips for encoding types
// - Prevention of accidental exfiltration


#[cfg(feature = "serde-serialize")]
#[test]
fn no_accidental_serialization_without_marker() {
    // This test demonstrates that types without ExportableType cannot be serialized
    // Fixed<u8> cannot be serialized because u8 doesn't impl ExportableType
    // We can't write a runtime test for this since it's a compile error, but this serves as documentation
    use secure_gate::Fixed;
    let _secret = Fixed::new(42u8);
    // serde_json::to_string(&_secret); // This would fail to compile if attempted
}
