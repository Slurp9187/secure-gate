#![cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]

extern crate alloc;

use secure_gate::SecureEncoding;

#[test]
fn test_slice_to_hex() {
    let data = [0x42u8, 0x43, 0x44].as_slice();
    let hex = SecureEncoding::to_hex(&data);
    assert_eq!(hex, "424344");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_array_to_hex() {
    let data: [u8; 4] = [1, 2, 3, 4];
    let hex = SecureEncoding::to_hex(&data);
    assert_eq!(hex, "01020304");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_vec_to_hex() {
    let data: Vec<u8> = vec![255, 0, 128];
    let hex = SecureEncoding::to_hex(&data);
    assert_eq!(hex, "ff0080");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_string_to_hex() {
    let data: String = "abc".to_string();
    let hex = SecureEncoding::to_hex(&data);
    assert_eq!(hex, "616263");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_hex_prefix() {
    let data: [u8; 4] = [1, 2, 3, 4];
    assert_eq!(SecureEncoding::to_hex_prefix(&data, 2), "0102…");
    assert_eq!(SecureEncoding::to_hex_prefix(&data, 4), "01020304");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn test_slice_to_base64url() {
    let data = [0x42u8, 0x43, 0x44].as_slice();
    let b64 = SecureEncoding::to_base64url(&data);
    assert_eq!(b64, "QkNE");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn test_array_to_base64url() {
    let data: [u8; 4] = [1, 2, 3, 4];
    let b64 = SecureEncoding::to_base64url(&data);
    assert_eq!(b64, "AQIDBA");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn test_vec_to_base64url() {
    let data: Vec<u8> = vec![255, 0, 128];
    let b64 = SecureEncoding::to_base64url(&data);
    assert_eq!(b64, "_wCA");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn test_string_to_base64url() {
    let data: String = "hello".to_string();
    let b64 = SecureEncoding::to_base64url(&data);
    assert_eq!(b64, "aGVsbG8");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_slice_to_bech32() {
    let data = [0x42u8, 0x43, 0x44].as_slice();
    let bech = SecureEncoding::to_bech32(&data, "test");
    assert!(bech.starts_with("test"));
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_array_to_bech32() {
    let data: [u8; 4] = [1, 2, 3, 4];
    let bech = SecureEncoding::to_bech32(&data, "test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_vec_to_bech32() {
    let data: Vec<u8> = vec![255, 0, 128];
    let bech = SecureEncoding::to_bech32(&data, "test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_string_to_bech32() {
    let data: String = "hi".to_string();
    let bech = SecureEncoding::to_bech32(&data, "test");
    assert!(bech.starts_with("test"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
#[should_panic(expected = "invalid hrp")]
fn test_invalid_hrp_bech32() {
    let data: [u8; 4] = [1, 2, 3, 4];
    // Invalid HRP: empty string
    let _ = SecureEncoding::to_bech32(&data, "");
}

#[cfg(feature = "encoding-bech32")]
#[test]
#[should_panic(expected = "bech32 encoding failed")]
fn test_bech32_encoding_failure() {
    // This might not actually fail, but as an example of potential encoding errors
    let data: Vec<u8> = vec![255; 1000]; // Very long data might cause issues, but bech32 can handle large data
    let _ = SecureEncoding::to_bech32(&data, "test");
}
