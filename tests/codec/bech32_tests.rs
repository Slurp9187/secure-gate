#![cfg(any(
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
    all(feature = "serde-deserialize", feature = "encoding-bech32")
))]

extern crate alloc;

use secure_gate::{FromBech32Str, FromBech32mStr, ToBech32, ToBech32m};

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

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_roundtrip() {
    use secure_gate::{ExposeSecret, Fixed};
    let original: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32("test"));
    let decoded = Fixed::try_from_bech32(&encoded).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn dynamic_try_from_bech32_roundtrip() {
    use secure_gate::{Dynamic, ExposeSecret};
    let original: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32("test"));
    let decoded = Dynamic::try_from_bech32(&encoded).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_roundtrip() {
    use secure_gate::{ExposeSecret, Fixed};
    let original: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32m("test"));
    let decoded = Fixed::try_from_bech32m(&encoded).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn dynamic_try_from_bech32m_roundtrip() {
    use secure_gate::{Dynamic, ExposeSecret};
    let original: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32m("test"));
    let decoded = Dynamic::try_from_bech32m(&encoded).unwrap();
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

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_string_from_bech32() {
    let data = [0x00];
    let encoded = data.to_bech32("test");
    let (hrp, decoded) = encoded.try_from_bech32().unwrap();
    assert_eq!(hrp, "test");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_string_from_bech32_expect_hrp() {
    let data = [0x00];
    let encoded = data.to_bech32("test");
    let decoded = encoded.try_from_bech32_expect_hrp("test").unwrap();
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_invalid_bech32_string() {
    let invalid = "invalid";
    let result = invalid.try_from_bech32();
    assert!(result.is_err());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_bech32_wrong_hrp() {
    let bech32 = "test1vejq2p";
    let result = bech32.try_from_bech32_expect_hrp("wrong");
    assert!(result.is_err());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_hrp_case_insensitive() {
    let data = [0x00u8; 1];
    let lower = data.to_bech32("test");
    let upper = data.to_bech32("TEST");
    assert_eq!(lower.to_ascii_lowercase(), upper.to_ascii_lowercase());

    let decoded_lower = lower.try_from_bech32_expect_hrp("test").unwrap();
    let decoded_upper = upper.try_from_bech32_expect_hrp("TEST").unwrap();
    assert_eq!(decoded_lower, decoded_upper);
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn test_string_from_bech32m() {
    let data = [0x00];
    let encoded = data.to_bech32m("test");
    let (hrp, decoded) = encoded.try_from_bech32m().unwrap();
    assert_eq!(hrp, "test");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn test_string_from_bech32m_expect_hrp() {
    let data = [0x00];
    let encoded = data.to_bech32m("test");
    let decoded = encoded.try_from_bech32m_expect_hrp("test").unwrap();
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn test_invalid_bech32m_string() {
    let invalid = "invalid";
    let result = invalid.try_from_bech32m();
    assert!(result.is_err());
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn test_bech32m_wrong_hrp() {
    let bech32m = "test1vw3q3p";
    let result = bech32m.try_from_bech32m_expect_hrp("wrong");
    assert!(result.is_err());
}

// Additional BIP-173/BIP-350 validation tests based on standard test vectors

#[cfg(feature = "encoding-bech32")]
#[test]
fn bip_173_valid_bech32_example() {
    // Valid Bech32 string: should decode with FromBech32Str, fail with FromBech32mStr
    let data = [0x00];
    let valid_bech32 = data.to_bech32("test");
    let result = valid_bech32.try_from_bech32();
    assert!(result.is_ok());
    let (hrp, bytes) = result.unwrap();
    assert_eq!(hrp, "test");
    assert_eq!(bytes, data);
    let result_bech32m = valid_bech32.try_from_bech32m();
    assert!(result_bech32m.is_err());
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bip_350_valid_bech32m_example() {
    // Valid Bech32m string: should decode with FromBech32mStr, fail with FromBech32Str
    let data = [0x01, 0x02];
    let valid_bech32m = data.to_bech32m("test");
    let result_bech32 = valid_bech32m.try_from_bech32();
    assert!(result_bech32.is_err());
    let result = valid_bech32m.try_from_bech32m();
    assert!(result.is_ok());
    let (hrp, bytes) = result.unwrap();
    assert_eq!(hrp, "test");
    assert_eq!(bytes, data);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bip_173_invalid_checksum() {
    // Invalid Bech32 checksum from BIP-173 test vectors
    let invalid = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5";
    let result = invalid.try_from_bech32();
    assert!(result.is_err());
    let result_bech32m = invalid.try_from_bech32m();
    assert!(result_bech32m.is_err()); // Also invalid as Bech32m
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bip_350_invalid_bech32m_checksum() {
    // String valid as Bech32 but invalid as Bech32m (checksum mismatch for Bech32m)
    let bech32_valid = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    // This should be invalid for Bech32m
    let result = bech32_valid.try_from_bech32m();
    assert!(result.is_err());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bip_173_empty_data_invalid() {
    // Empty data section from BIP-173 test vectors (invalid)
    let invalid = "bc1gmk9yu";
    let result = invalid.try_from_bech32();
    assert!(result.is_err());
}


