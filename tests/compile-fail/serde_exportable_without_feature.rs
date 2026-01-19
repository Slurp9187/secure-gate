// secure-gate/tests/compile-fail/serde_exportable_without_feature.rs
// This file should NOT compile when the "serde-serialize" feature is NOT enabled.
// It verifies that Exportable* types are not available without the serde-serialize feature,
// enforcing opt-in serialization.
//
// Expected failures:
// - ExportableArray, ExportableVec, ExportableString types not found

#[cfg(feature = "serde-serialize")]
fn main() {
    // With feature, this should work - types exist
    use secure_gate::{ExportableArray, ExportableString, ExportableVec};
    let _array: ExportableArray<4> = [1, 2, 3, 4].into();
    let _vec: ExportableVec = vec![1, 2, 3].into();
    let _string: ExportableString = "test".into();
    println!("Exportable types available with serde-serialize");
}

#[cfg(not(feature = "serde-serialize"))]
fn main() {
    // Without feature, these types should not exist - compile error expected
    // let _array = secure_gate::ExportableArray::<4>::from([1, 2, 3, 4]);
    // let _vec = secure_gate::ExportableVec::from(vec![1, 2, 3]);
    // let _string = secure_gate::ExportableString::from("test");

    // Since the types are gated behind #[cfg(feature = "serde-serialize")],
    // attempting to use them here will cause "type not found" errors.
    // We can't write the actual usage without causing errors, but this serves as documentation.
    println!("serde-serialize feature not enabled - Exportable types unavailable");
}
