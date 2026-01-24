#![cfg(any(
    feature = "encoding-base64",
    all(feature = "serde-deserialize", feature = "encoding-base64")
))]

extern crate alloc;

use secure_gate::SecureEncoding;

#[cfg(feature = "encoding-base64")]
#[test]
fn test_slice_to_base64url() {
    let data = [0x42u8, 0x43, 0x44].as_slice();
    let b64 = data.to_base64url();
    assert_eq!(b64, "QkNE");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn test_array_to_base64url() {
    let data: [u8; 4] = [1, 2, 3, 4];
    let b64 = data.to_base64url();
    assert_eq!(b64, "AQIDBA");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn test_vec_to_base64url() {
    let data: Vec<u8> = vec![255, 0, 128];
    let b64 = data.to_base64url();
    assert_eq!(b64, "_wCA");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn test_string_to_base64url() {
    let data: String = "hello".to_string();
    let b64 = data.to_base64url();
    assert_eq!(b64, "aGVsbG8");
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
#[test]
fn fixed_deserialize_base64_string() {
    use secure_gate::{ExposeSecret, Fixed};
    // Valid base64 for 4 bytes: "AQIDBA=="
    let result: Fixed<[u8; 4]> = serde_json::from_str("\"AQIDBA\"").unwrap();
    result.with_secret(|r| assert_eq!(r, &[1, 2, 3, 4]));
    // Invalid: wrong length
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("\"AQ\""); // 1 byte
    assert!(result.is_err());
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
#[test]
fn dynamic_deserialize_base64_string() {
    use secure_gate::{Dynamic, ExposeSecret};
    // Valid base64
    let result: Dynamic<Vec<u8>> = serde_json::from_str("\"AQIDBA\"").unwrap();
    result.with_secret(|r| assert_eq!(r, &[1, 2, 3, 4]));
}
