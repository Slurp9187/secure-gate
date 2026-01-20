// tests/compile-fail/serde_core_without_marker.rs
// This file should NOT compile when the "serde-serialize" feature is enabled.
// It verifies that core wrappers (Fixed<T>, Dynamic<T>) cannot be serialized
// without an explicit user-provided impl ExportableType for the inner type T.
//
// Expected failures:
// - No Serialize for Fixed<[u8; 32]> (missing ExportableType on [u8; 32])
// - No Serialize for Dynamic<String> (missing ExportableType on String)

#[cfg(feature = "serde-serialize")]
fn main() {
    use secure_gate::{Dynamic, Fixed};

    let fixed: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
    let dyn_str: Dynamic<String> = "test".into();

    // These lines must cause compile errors due to missing ExportableType
    let _ = serde_json::to_string(&fixed);
    let _ = serde_json::to_string(&dyn_str);
}

#[cfg(not(feature = "serde-serialize"))]
fn main() {
    // When serde-serialize is disabled, this test is irrelevant and should not run.
    // trybuild will skip or pass empty mains.
}
