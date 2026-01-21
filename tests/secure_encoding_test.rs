#![cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]

extern crate alloc;

use secure_gate::{
    cloneable_dynamic_alias, cloneable_fixed_alias, serializable_dynamic_alias,
    serializable_fixed_alias, ExposeSecret, SecureEncoding,
};

// Define test types using macros
cloneable_fixed_alias!(pub TestCloneableArray, 4);
cloneable_dynamic_alias!(pub TestCloneableString, String);
cloneable_dynamic_alias!(pub TestCloneableVec, Vec<u8>);
serializable_fixed_alias!(pub TestSerializableArray, 4);
serializable_dynamic_alias!(pub TestSerializableString, String);
serializable_dynamic_alias!(pub TestSerializableVec, Vec<u8>);

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

#[test]
fn test_vec_to_hex() {
    let data: Vec<u8> = vec![255, 0, 128];
    let hex = data.to_hex();
    assert_eq!(hex, "ff0080");
}

#[test]
fn test_string_to_hex() {
    let data: String = "abc".to_string();
    let hex = data.to_hex();
    assert_eq!(hex, "616263");
}

#[test]
fn test_slice_to_base64url() {
    let data = [0x42u8, 0x43, 0x44].as_slice();
    let b64 = data.to_base64url();
    assert_eq!(b64, "QkNE");
}

#[test]
fn test_array_to_base64url() {
    let data: [u8; 4] = [1, 2, 3, 4];
    let b64 = data.to_base64url();
    assert_eq!(b64, "AQIDBA");
}

#[test]
fn test_vec_to_base64url() {
    let data: Vec<u8> = vec![255, 0, 128];
    let b64 = data.to_base64url();
    assert_eq!(b64, "_wCA");
}

#[test]
fn test_string_to_base64url() {
    let data: String = "hello".to_string();
    let b64 = data.to_base64url();
    assert_eq!(b64, "aGVsbG8");
}

#[test]
fn test_slice_to_bech32() {
    let data = [0x42u8, 0x43, 0x44].as_slice();
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test"));
    assert!(bech.starts_with("test"));
}

#[test]
fn test_array_to_bech32() {
    let data: [u8; 4] = [1, 2, 3, 4];
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test"));
}

#[test]
fn test_vec_to_bech32() {
    let data: Vec<u8> = vec![255, 0, 128];
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test"));
}

#[test]
fn test_string_to_bech32() {
    let data: String = "hi".to_string();
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test"));
}

#[test]
fn test_cloneable_array_to_hex() {
    let data: TestCloneableArray = [1u8, 2, 3, 4].into();
    let hex = data.to_hex();
    assert_eq!(hex, "01020304");
}

#[test]
fn test_cloneable_vec_to_hex() {
    let data: TestCloneableVec = vec![255, 0, 128].into();
    let hex = data.to_hex();
    assert_eq!(hex, "ff0080");
}

#[test]
fn test_cloneable_array_to_base64url() {
    let data: TestCloneableArray = [1u8, 2, 3, 4].into();
    let b64 = data.to_base64url();
    assert_eq!(b64, "AQIDBA");
}

#[test]
fn test_cloneable_vec_to_bech32() {
    let data: TestCloneableVec = vec![255, 0, 128].into();
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test"));
}

#[test]
fn test_exportable_string_to_hex() {
    let data: TestSerializableString = "abc".to_string().into();
    let hex = data.to_hex();
    assert_eq!(hex, "616263");
}

#[test]
fn test_exportable_vec_to_base64url() {
    let data: TestSerializableVec = vec![1, 2, 3].into();
    let b64 = data.to_base64url();
    assert_eq!(b64, "AQID");
}

#[test]
fn test_exportable_array_to_bech32() {
    let data: TestSerializableArray = [1u8, 2, 3, 4].into();
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test"));
}

#[test]
fn test_cloneable_string_to_hex() {
    let data: TestCloneableString = "test".to_string().into();
    let hex = data.to_hex();
    assert_eq!(hex, "74657374");
}

#[test]
fn test_exportable_string_to_base64url() {
    let data: TestSerializableString = "hello".to_string().into();
    let b64 = data.to_base64url();
    assert_eq!(b64, "aGVsbG8");
}

#[test]
fn test_cloneable_string_to_bech32() {
    let data: TestCloneableString = "hi".to_string().into();
    let bech = data.to_bech32("test");
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
