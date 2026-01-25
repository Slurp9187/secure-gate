#![cfg(any(
    feature = "encoding-hex",
    all(feature = "serde-deserialize", feature = "encoding-hex")
))]

extern crate alloc;

use secure_gate::{FromHexStr, ToHex};

#[cfg(feature = "encoding-hex")]
#[test]
fn test_slice_to_hex() {
    let data = [0x42u8, 0x43, 0x44].as_slice();
    let hex = data.to_hex();
    assert_eq!(hex, "424344");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_array_to_hex() {
    let data: [u8; 4] = [1, 2, 3, 4];
    let hex = data.to_hex();
    assert_eq!(hex, "01020304");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_vec_to_hex() {
    let data: Vec<u8> = vec![255, 0, 128];
    let hex = data.to_hex();
    assert_eq!(hex, "ff0080");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_string_to_hex() {
    let data: String = "abc".to_string();
    let hex = data.to_hex();
    assert_eq!(hex, "616263");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_hex_left() {
    let data: [u8; 4] = [1, 2, 3, 4];
    assert_eq!(data.to_hex_left(2), "0102…");
    assert_eq!(data.to_hex_left(4), "01020304");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_string_from_hex() {
    let hex = "424344";
    let bytes = hex.try_from_hex().unwrap();
    assert_eq!(bytes, vec![0x42, 0x43, 0x44]);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_invalid_hex_string() {
    let invalid_hex = "gg"; // 'g' is not a hex char
    let result = invalid_hex.try_from_hex();
    assert!(result.is_err());
}

// Demonstrate umbrella trait: types implementing AsRef<[u8]> get SecureEncoding
// Demonstrate umbrella trait: types implementing AsRef<[u8]> get SecureEncoding when encoding features are enabled
#[cfg(feature = "encoding-hex")]
#[test]
fn test_secure_encoding_umbrella() {
    // Any AsRef<[u8]> type implements SecureEncoding when encoding features are enabled
    let data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
    // This works because ToHex is blanket-implemented over AsRef<[u8]>
    assert!(data.to_hex() == "deadbeef");
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
#[test]
fn fixed_deserialize_hex_string() {
    use secure_gate::{ExposeSecret, Fixed};
    // Valid hex string for 4 bytes
    let result: Fixed<[u8; 4]> = serde_json::from_str("\"deadbeef\"").unwrap();
    result.with_secret(|r| assert_eq!(r, &[0xde, 0xad, 0xbe, 0xef]));
    // Invalid length: hex for 2 bytes
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("\"dead\"");
    assert!(result.is_err());
}
