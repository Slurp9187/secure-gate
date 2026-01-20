// This file should NOT compile when "serde-serialize" and "zeroize" are enabled.
// It verifies that cloneable wrappers cannot be serialized without an explicit
// user-provided impl ExportableType for the inner type.
//
// Expected failures:
// - No Serialize for CloneableString (missing marker on String)
// - No Serialize for CloneableVec (missing marker on Vec<u8>)
// - No Serialize for CloneableArray<32> (missing marker on [u8; 32])

#[cfg(all(feature = "serde-serialize", feature = "zeroize"))]
fn main() {
    use secure_gate::{CloneableArray, CloneableString, CloneableVec};

    let pw: CloneableString = "secret".into();
    let data: CloneableVec = vec![0u8; 128].into();
    let key: CloneableArray<32> = [0u8; 32].into();

    // These lines must cause compile errors due to missing ExportableType
    let _ = serde_json::to_string(&pw);
    let _ = serde_json::to_string(&data);
    let _ = serde_json::to_string(&key);
}

#[cfg(not(all(feature = "serde-serialize", feature = "zeroize")))]
fn main() {
    // Irrelevant when features disabled
}
