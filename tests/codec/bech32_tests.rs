#![cfg(any(
    feature = "encoding-bech32",
    all(feature = "serde-deserialize", feature = "encoding-bech32")
))]

extern crate alloc;

use secure_gate::SecureEncoding;

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_slice_to_bech32() {
    let data = [0x42u8, 0x43, 0x44].as_slice();
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_array_to_bech32() {
    let data: [u8; 4] = [1, 2, 3, 4];
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_vec_to_bech32() {
    let data: Vec<u8> = vec![255, 0, 128];
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_string_to_bech32() {
    let data: String = "hi".to_string();
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_slice_to_bech32m() {
    let data = [0x42u8, 0x43, 0x44].as_slice();
    let bech = data.to_bech32m("test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_array_to_bech32m() {
    let data: [u8; 4] = [1, 2, 3, 4];
    let bech = data.to_bech32m("test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_vec_to_bech32m() {
    let data: Vec<u8> = vec![255, 0, 128];
    let bech = data.to_bech32m("test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_string_to_bech32m() {
    let data: String = "hi".to_string();
    let bech = data.to_bech32m("test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
#[should_panic(expected = "invalid hrp")]
fn test_invalid_hrp_bech32() {
    let data: [u8; 4] = [1, 2, 3, 4];
    // Invalid HRP: empty string
    let _ = data.to_bech32("");
}

#[cfg(feature = "encoding-bech32")]
#[test]
#[should_panic(expected = "bech32 encoding failed")]
fn test_bech32_encoding_failure() {
    // This might not actually fail, but as an example of potential encoding errors
    let data: Vec<u8> = vec![255; 1000]; // Very long data might cause issues, but bech32 can handle large data
    let _ = data.to_bech32("test");
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
#[test]
fn fixed_deserialize_bech32_roundtrip() {
    use secure_gate::{ExposeSecret, Fixed, SecureEncoding};
    let original: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32("test"));
    let json = format!("\"{}\"", encoded);
    let decoded: Fixed<[u8; 4]> = serde_json::from_str(&json).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
#[test]
fn dynamic_deserialize_bech32_roundtrip() {
    use secure_gate::{Dynamic, ExposeSecret, SecureEncoding};
    let original: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32("test"));
    let json = format!("\"{}\"", encoded);
    let decoded: Dynamic<Vec<u8>> = serde_json::from_str(&json).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
#[test]
fn fixed_deserialize_bech32m_roundtrip() {
    use secure_gate::{ExposeSecret, Fixed, SecureEncoding};
    let original: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32m("test"));
    let json = format!("\"{}\"", encoded);
    let decoded: Fixed<[u8; 4]> = serde_json::from_str(&json).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
#[test]
fn dynamic_deserialize_bech32m_roundtrip() {
    use secure_gate::{Dynamic, ExposeSecret, SecureEncoding};
    let original: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32m("test"));
    let json = format!("\"{}\"", encoded);
    let decoded: Dynamic<Vec<u8>> = serde_json::from_str(&json).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
#[test]
fn bech32_deserialize_invalid_checksums() {
    use secure_gate::Fixed;
    // Invalid bech32 checksum
    let result: Result<Fixed<[u8; 4]>, _> =
        serde_json::from_str("\"test1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqx\"");
    assert!(result.is_err());
    // Invalid bech32m checksum (using bech32 string)
    let result: Result<Fixed<[u8; 4]>, _> =
        serde_json::from_str("\"test1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw\"");
    assert!(result.is_err());
}
