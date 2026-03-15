#![cfg(any(
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
    all(feature = "serde-deserialize", feature = "encoding-bech32")
))]

extern crate alloc;

use secure_gate::{
    Dynamic, ExposeSecret, Fixed, FromBech32Str, FromBech32mStr, ToBech32, ToBech32m,
};

macro_rules! test_encoding {
    ($method:ident, $try_from:ident, $data:expr, $hrp:expr) => {{
        let data_ref: &[u8] = $data.as_ref();
        let encoded = data_ref.$method($hrp);
        assert!(encoded.starts_with($hrp));
        let (decoded_hrp, decoded) = encoded.$try_from().expect("valid encoding");
        assert_eq!(decoded_hrp.to_ascii_lowercase(), $hrp.to_ascii_lowercase());
        assert_eq!(decoded, data_ref.to_vec());
    }};
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_slice_to_bech32() {
    let data = [0x42u8, 0x43, 0x44];
    test_encoding!(to_bech32, try_from_bech32, &data[..], "test");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_array_to_bech32() {
    let data: [u8; 4] = [1, 2, 3, 4];
    test_encoding!(to_bech32, try_from_bech32, &data, "test");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_vec_to_bech32() {
    let data: Vec<u8> = vec![255, 0, 128];
    test_encoding!(to_bech32, try_from_bech32, &data, "test");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_string_to_bech32() {
    let data: String = "hi".to_string();
    test_encoding!(to_bech32, try_from_bech32, data.as_bytes(), "test");
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn test_slice_to_bech32m() {
    let data = [0x42u8, 0x43, 0x44];
    test_encoding!(to_bech32m, try_from_bech32m, &data[..], "test");
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn test_array_to_bech32m() {
    let data: [u8; 4] = [1, 2, 3, 4];
    test_encoding!(to_bech32m, try_from_bech32m, &data, "test");
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn test_vec_to_bech32m() {
    let data: Vec<u8> = vec![255, 0, 128];
    test_encoding!(to_bech32m, try_from_bech32m, &data, "test");
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn test_string_to_bech32m() {
    let data: String = "hi".to_string();
    test_encoding!(to_bech32m, try_from_bech32m, data.as_bytes(), "test");
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
fn test_bech32_large_success() {
    let data: Vec<u8> = vec![255u8; 1000]; // Large data, with Bech32 checksum (CODE_LENGTH=4096)
    let bech = data.to_bech32("test");
    assert!(bech.starts_with("test1"));
    // Roundtrip verify
    let (hrp, decoded) = bech.try_from_bech32().unwrap();
    assert_eq!(hrp, "test");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32m")]
#[test]
#[should_panic(expected = "TooLong")]
fn test_bech32m_large_failure() {
    let data: Vec<u8> = vec![255u8; 1000]; // Standard Bech32m is limited (~520 bytes max)
    let _ = data.to_bech32m("test");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_roundtrip() {
    let original: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32("test"));
    let decoded = Fixed::try_from_bech32(&encoded).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn dynamic_try_from_bech32_roundtrip() {
    let original: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32("test"));
    let decoded = Dynamic::try_from_bech32(&encoded).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_roundtrip() {
    let original: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32m("test"));
    let decoded = Fixed::try_from_bech32m(&encoded).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn dynamic_try_from_bech32m_roundtrip() {
    let original: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32m("test"));
    let decoded = Dynamic::try_from_bech32m(&encoded).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
#[test]
fn bech32_deserialize_invalid_checksums() {
    use serde_json;
    // Invalid bech32 checksum
    let result: Result<String, _> =
        serde_json::from_str(r#""test1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqx""#);
    if let Ok(s) = result {
        let decode_result = Fixed::<[u8; 4]>::try_from_bech32(&s);
        assert!(decode_result.is_err());
    } else {
        panic!("Unexpected JSON error");
    }
    // Invalid bech32m checksum (using bech32 string)
    let result: Result<String, _> =
        serde_json::from_str(r#""test1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw""#);
    if let Ok(s) = result {
        let decode_result = Fixed::<[u8; 4]>::try_from_bech32(&s);
        assert!(decode_result.is_err());
    } else {
        panic!("Unexpected JSON error");
    }
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
#[test]
fn bech32_serde_roundtrip() {
    use serde_json;
    let original: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    let encoded = original.with_secret(|s| s.to_bech32("test"));
    let json = serde_json::to_string(&encoded).unwrap();
    let decoded_str: String = serde_json::from_str(&json).unwrap();
    let decoded: Fixed<[u8; 4]> = Fixed::try_from_bech32(&decoded_str).unwrap();
    original.with_secret(|o| decoded.with_secret(|d| assert_eq!(o, d)));
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
    #[cfg(feature = "encoding-bech32m")]
    {
        let result_bech32m = valid_bech32.try_from_bech32m();
        assert!(result_bech32m.is_err());
    }
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bip_350_valid_bech32m_example() {
    // Valid Bech32m string: should decode with FromBech32mStr, fail with FromBech32Str
    let data = [0x01, 0x02];
    let valid_bech32m = data.to_bech32m("test");
    #[cfg(feature = "encoding-bech32")]
    {
        let result_bech32 = valid_bech32m.try_from_bech32();
        assert!(result_bech32.is_err());
    }
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
    #[cfg(feature = "encoding-bech32m")]
    {
        let result_bech32m = invalid.try_from_bech32m();
        assert!(result_bech32m.is_err()); // Also invalid as Bech32m
    }
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
fn bip_173_invalid_mixed_case() {
    // Invalid mixed case from BIP-173 test vectors
    let invalid = "a1l2Pn"; // Actual mixed case invalid example from BIP
    let result = invalid.try_from_bech32();
    assert!(result.is_err());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bip_173_invalid_length() {
    // Invalid too-long HRP from BIP-173 test vectors
    let invalid = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx";
    let result = invalid.try_from_bech32();
    assert!(result.is_err());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bip_173_empty_data_example() {
    // Empty data section from BIP-173 test vectors (valid for general-purpose Bech32, though invalid for SegWit)
    let example = "bc1gmk9yu";
    let result = example.try_from_bech32();
    assert!(result.is_ok());
    let (hrp, data) = result.unwrap();
    assert_eq!(hrp, "bc");
    assert!(data.is_empty());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_bech32_hrp_containing_1() {
    let data = [0x00u8; 1];
    let bech = data.to_bech32("test1");
    assert!(bech.starts_with("test11"));
    let (hrp, decoded) = bech.try_from_bech32().unwrap();
    assert_eq!(hrp, "test1");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn test_bech32m_hrp_containing_1() {
    let data = [0x00u8; 1];
    let bech = data.to_bech32m("test1");
    assert!(bech.starts_with("test11"));
    let (hrp, decoded) = bech.try_from_bech32m().unwrap();
    assert_eq!(hrp, "test1");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32")]
proptest::proptest! {
    #[test]
    fn proptest_bech32_roundtrip(data in proptest::collection::vec(0u8..=255, 0..100)) {
        let encoded = data.to_bech32("test");
        let (_, decoded) = encoded.try_from_bech32().expect("valid roundtrip");
        proptest::prop_assert_eq!(decoded, data);
    }
}

#[cfg(feature = "encoding-bech32m")]
proptest::proptest! {
    #[test]
    fn proptest_bech32m_roundtrip(data in proptest::collection::vec(0u8..=255, 0..100)) {
        let encoded = data.to_bech32m("test");
        let (_, decoded) = encoded.try_from_bech32m().expect("valid roundtrip");
        proptest::prop_assert_eq!(decoded, data);
    }
}
