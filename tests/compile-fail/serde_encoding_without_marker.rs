// tests/compile-fail/serde_encoding_without_marker.rs
// This file should NOT compile when "serde-serialize" and the respective encoding
// feature is enabled.
// It verifies that encoding wrappers (HexString, Base64String, Bech32String)
// cannot be serialized without an explicit user-provided impl SerializableSecret
// for the inner type (String).
//
// Expected failure (for each enabled encoding):
// - No Serialize due to missing SerializableSecret on String

#[cfg(all(feature = "serde-serialize", feature = "encoding-hex"))]
fn hex_test() {
    use secure_gate::encoding::hex::HexString;

    let hex = HexString::new("deadbeef".to_string()).unwrap();

    // This line must cause compile error: no SerializableSecret on String
    let _ = serde_json::to_string(&hex);
}

#[cfg(all(feature = "serde-serialize", feature = "encoding-base64"))]
fn base64_test() {
    use secure_gate::encoding::base64::Base64String;

    let b64 = Base64String::new("SGVsbG8gV29ybGQ".to_string()).unwrap();

    // This line must cause compile error: no SerializableSecret on String
    let _ = serde_json::to_string(&b64);
}

#[cfg(all(feature = "serde-serialize", feature = "encoding-bech32"))]
fn bech32_test() {
    use secure_gate::encoding::bech32::Bech32String;

    let bech32 = Bech32String::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()).unwrap();

    // This line must cause compile error: no SerializableSecret on String
    let _ = serde_json::to_string(&bech32);
}

// Fallback empty main when no relevant features enabled
#[cfg(not(any(
    all(feature = "serde-serialize", feature = "encoding-hex"),
    all(feature = "serde-serialize", feature = "encoding-base64"),
    all(feature = "serde-serialize", feature = "encoding-bech32")
)))]
fn main() {}
