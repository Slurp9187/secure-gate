// ==========================================================================
// tests/encoding/base64_tests.rs
// ==========================================================================
// Tests for base64 encoding.

#![cfg(test)]

use base64::Engine;
#[cfg(feature = "rand")]
use secure_gate::fixed_alias_random;
use secure_gate::Base64String;
use secure_gate::ExposeSecret;
#[cfg(feature = "rand")]
use secure_gate::SecureEncodingExt;

#[cfg(feature = "encoding-base64")]
#[cfg(feature = "rand")]
#[test]
fn into_base64url_via_alias() {
    fixed_alias_random!(Base64Key, 32);

    let key = Base64Key::generate();
    let b64_str = key.expose_secret().to_base64url();
    let b64 = b64_str;

    // URL-safe base64, no padding
    assert!(b64
        .expose_secret()
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

    let bytes = b64.into_bytes();
    assert_eq!(bytes.len(), 32);
}

#[cfg(feature = "encoding-base64")]
#[test]
fn base64string_new_rejects_invalid() {
    // Invalid character
    let s = "!".to_string();
    let err = Base64String::new(s).unwrap_err();
    assert_eq!(err, "invalid base64 string");

    // Padding (not allowed in no-pad)
    let s = "QQ==".to_string();
    let err = Base64String::new(s).unwrap_err();
    assert_eq!(err, "invalid base64 string");

    // Incomplete base64 (odd length not multiple of 4)
    let s = "SGV".to_string();
    let err = Base64String::new(s).unwrap_err();
    assert_eq!(err, "invalid base64 string");

    // Single char invalid
    let s = "A".to_string();
    let err = Base64String::new(s).unwrap_err();
    assert_eq!(err, "invalid base64 string");

    // Invalid char in middle
    let s = "QUJD!".to_string();
    let err = Base64String::new(s).unwrap_err();
    assert_eq!(err, "invalid base64 string");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn base64string_valid_parsing() {
    let s = "SGVsbG8".to_string(); // "Hello"
    let b64 = Base64String::new(s).unwrap();
    assert_eq!(b64.expose_secret(), "SGVsbG8");
    assert_eq!(b64.len(), 7);
    assert_eq!(b64.byte_len(), 5);

    let bytes = b64.into_bytes();
    assert_eq!(bytes, b"Hello");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn base64string_empty() {
    let b64 = Base64String::new("".to_string()).unwrap();
    assert_eq!(b64.expose_secret(), "");
    assert_eq!(b64.len(), 0);
    assert_eq!(b64.byte_len(), 0);
    assert!(b64.is_empty());
    assert_eq!(b64.into_bytes(), Vec::<u8>::new());
}

#[cfg(feature = "encoding-base64")]
#[test]
fn base64string_byte_len_correct() {
    // 2 chars -> 1 byte
    let b64 = Base64String::new("QQ".to_string()).unwrap();
    assert_eq!(b64.byte_len(), 1);

    // 3 chars -> 2 bytes
    let b64 = Base64String::new("QUE".to_string()).unwrap();
    assert_eq!(b64.byte_len(), 2);

    // 4 chars -> 3 bytes
    let b64 = Base64String::new("QUJD".to_string()).unwrap();
    assert_eq!(b64.byte_len(), 3);

    // 8 chars -> 6 bytes
    let b64 = Base64String::new("QUJDREVG".to_string()).unwrap();
    assert_eq!(b64.byte_len(), 6);
}

#[cfg(feature = "encoding-base64")]
#[cfg(feature = "ct-eq")]
#[test]
fn base64string_constant_time_eq() {
    let s1 = "SGVsbG8".to_string();
    let s2 = "SGVsbG8".to_string();
    let b64_1 = Base64String::new(s1).unwrap();
    let b64_2 = Base64String::new(s2).unwrap();
    assert_eq!(b64_1, b64_2);

    // Test unequal
    let s3 = "dGVzdA".to_string(); // "test"
    let b64_3 = Base64String::new(s3).unwrap();
    assert_ne!(b64_1, b64_3);
}

#[cfg(feature = "encoding-base64")]
#[test]
fn base64string_decode_borrowing() {
    let b64 = Base64String::new("SGVsbG8".to_string()).unwrap();
    let bytes = b64.decode();
    assert_eq!(bytes, b"Hello");
    // Verify b64 is still usable (borrowing)
    let bytes2 = b64.decode();
    assert_eq!(bytes2, bytes);
}

#[cfg(feature = "encoding-base64")]
#[test]
fn base64string_case_sensitive() {
    // Test round-trip consistency for encoding/decoding.
    let original_bytes = b"Hello";
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(original_bytes);
    let b64 = Base64String::new(encoded).unwrap();
    let decoded = b64.into_bytes();
    assert_eq!(decoded, original_bytes);
}

#[cfg(all(feature = "encoding-base64", feature = "rand"))]
#[test]
fn rng_base64url_integration() {
    use secure_gate::random::FixedRandom;
    let rng = FixedRandom::<32>::generate();
    let b64 = rng.into_base64url();
    assert_eq!(b64.into_bytes().len(), 32);
}
