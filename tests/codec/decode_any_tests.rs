#![cfg(all(
    feature = "serde-deserialize",
    any(
        feature = "encoding-hex",
        feature = "encoding-base64",
        feature = "encoding-bech32"
    )
))]

extern crate alloc;

use secure_gate::utilities::decoding::{try_decode_any, Format};
use secure_gate::DecodingError;

#[cfg(all(feature = "encoding-hex", feature = "encoding-base64"))]
#[test]
fn decode_any_prefers_hex_then_base64() {
    // A string that is valid hex and also valid base64url → should pick hex since hex succeeds first
    let ambiguous = "deadbeef"; // valid hex (decodes to [0xde, 0xad, 0xbe, 0xef]), also valid base64url (decodes to different bytes)
    let decoded = try_decode_any(ambiguous, None).unwrap();
    assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]); // Should be hex decode
}

#[test]
fn decode_any_default_order() {
    // Default should try Bech32 → Hex → Base64Url
    let hex_input = "deadbeef";
    let decoded = try_decode_any(hex_input, None).unwrap();
    assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);

    // Invalid should fail
    let invalid = "invalid!!!";
    assert!(try_decode_any(invalid, None).is_err());
}

#[test]
fn decode_any_hex_only() {
    let hex_input = "deadbeef";
    let decoded = try_decode_any(hex_input, Some(&[Format::Hex])).unwrap();
    assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);

    // Non-hex should fail
    let non_hex = "SGVsbG8="; // valid base64
    assert!(try_decode_any(non_hex, Some(&[Format::Hex])).is_err());
}

#[test]
fn decode_any_base64_only() {
    let base64_input = "SGVsbG8=";
    let decoded = try_decode_any(base64_input, Some(&[Format::Base64Url])).unwrap();
    assert_eq!(decoded, b"Hello");

    // Non-base64 should fail
    let non_base64 = "invalid!!!"; // invalid chars for base64
    assert!(try_decode_any(non_base64, Some(&[Format::Base64Url])).is_err());
}

#[test]
fn decode_any_custom_order() {
    let base64_input = "SGVsbG8=";
    // Custom order: Base64Url first, then Hex
    let decoded = try_decode_any(base64_input, Some(&[Format::Base64Url, Format::Hex])).unwrap();
    assert_eq!(decoded, b"Hello");

    // Same input with different order: Hex first (should fail Hex, then succeed Base64Url)
    let decoded2 = try_decode_any(base64_input, Some(&[Format::Hex, Format::Base64Url])).unwrap();
    assert_eq!(decoded2, b"Hello");
}

#[test]
fn decode_any_empty_priority() {
    let hex_input = "deadbeef";
    // Empty slice should fail all
    assert!(try_decode_any(hex_input, Some(&[])).is_err());
}

#[test]
fn decode_any_error_hint() {
    let result = try_decode_any("invalid!!!", None);
    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        DecodingError::InvalidEncoding { hint } => {
            assert!(hint.contains("Attempted order"));
            assert!(hint.contains("Bech32"));
            assert!(hint.contains("Hex"));
            assert!(hint.contains("Base64Url"));
        }
        _ => panic!("Expected InvalidEncoding"),
    }
}

#[cfg(all(feature = "encoding-bech32", feature = "encoding-hex"))]
#[test]
fn decode_any_bech32_priority() {
    // Valid Bech32 string
    let bech32_input = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    // Default order should decode Bech32
    let decoded = try_decode_any(bech32_input, None).unwrap();
    assert!(!decoded.is_empty()); // Basic check

    // Strict Bech32 only
    let decoded2 = try_decode_any(bech32_input, Some(&[Format::Bech32])).unwrap();
    assert_eq!(decoded, decoded2);
}
