// ==========================================================================
// tests/conversions_tests.rs
// ==========================================================================
// Comprehensive testing for conversions functionality

#![cfg(feature = "conversions")]

use secure_gate::{dynamic_alias, fixed_alias, HexString, RandomHex, SecureConversionsExt};

#[cfg(feature = "rand")]
use secure_gate::{Dynamic, Fixed, rng::{DynamicRng, FixedRng}};

// ──────────────────────────────────────────────────────────────
// Basic conversions functionality
// ──────────────────────────────────────────────────────────────

dynamic_alias!(TestKey, Vec<u8>);
dynamic_alias!(Nonce, Vec<u8>);
dynamic_alias!(SmallKey, Vec<u8>);
dynamic_alias!(MyKey, Vec<u8>);

#[test]
fn to_hex_and_to_hex_upper() {
    let bytes = vec![
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
        0xBA, 0x98,
    ];
    let key: TestKey = bytes.into();

    assert_eq!(
        key.expose_secret().to_hex(),
        "deadbeef00112233445566778899aabbccddeeff0123456789abcdeffedcba98"
    );
    assert_eq!(
        key.expose_secret().to_hex_upper(),
        "DEADBEEF00112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98"
    );
}

#[test]
fn to_base64url() {
    let key = TestKey::from(vec![
        0xFB, 0x7C, 0xD5, 0x7F, 0x83, 0xA5, 0xA5, 0x6D, 0xC2, 0xC7, 0x2F, 0xD0, 0x3E, 0xA0, 0xE0,
        0xF0, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E,
        0x8F, 0x90,
    ]);

    assert_eq!(
        key.expose_secret().to_base64url(),
        "-3zVf4OlpW3Cxy_QPqDg8KGyw9Tl9gcYKTpLXG1-j5A"
    );
}

#[test]
fn ct_eq_same_key() {
    let key1 = TestKey::from(vec![1u8; 32]);
    let key2 = TestKey::from(vec![1u8; 32]);
    assert!(key1.expose_secret().ct_eq(key2.expose_secret()));
}

#[test]
fn ct_eq_different_keys() {
    let key1 = TestKey::from(vec![1u8; 32]);
    let key2 = TestKey::from(vec![2u8; 32]);
    let mut bytes = vec![1u8; 32];
    bytes[31] = 9;
    let key3 = TestKey::from(bytes);

    assert!(!key1.expose_secret().ct_eq(key2.expose_secret()));
    assert!(!key1.expose_secret().ct_eq(key3.expose_secret()));
}

#[test]
fn works_on_all_dynamic_alias_sizes() {
    let nonce: Nonce = vec![0xFFu8; 24].into();
    let small: SmallKey = vec![0xAAu8; 16].into();

    assert_eq!(nonce.expose_secret().to_hex().len(), 48);
    assert_eq!(small.expose_secret().to_hex().len(), 32);
    assert_eq!(nonce.expose_secret().to_base64url().len(), 32);
    assert_eq!(small.expose_secret().to_base64url().len(), 22);
}

#[test]
fn trait_is_available_on_dynamic_alias_types() {
    let key = MyKey::from(vec![0x42u8; 32]);
    let _ = key.expose_secret().to_hex();
    let _ = key.expose_secret().to_base64url();
    let _ = key.expose_secret().ct_eq(key.expose_secret());
}

#[test]
fn hex_string_validates_and_decodes() {
    let valid = "a1b2c3d4e5f67890".to_string();
    let hex = HexString::new(valid).unwrap();
    assert_eq!(hex.expose_secret(), "a1b2c3d4e5f67890");
    assert_eq!(hex.byte_len(), 8);
    assert_eq!(
        hex.to_bytes(),
        vec![0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78, 0x90]
    );
    let invalid = "a1b2c3d".to_string();
    assert!(HexString::new(invalid).is_err());
}

#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn random_hex_returns_randomhex() {
    use secure_gate::rng::FixedRng;
    let hex: RandomHex = FixedRng::<32>::random_hex();
    assert_eq!(hex.expose_secret().len(), 64);
    assert!(hex.expose_secret().chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hex.to_bytes().len(), 32);
}

#[test]
fn ct_eq_different_lengths_returns_false() {
    dynamic_alias!(TestKey, Vec<u8>);
    let a = TestKey::from(vec![0u8; 32]);
    let b = TestKey::from(vec![0u8; 64]);
    assert!(!a.expose_secret().ct_eq(b.expose_secret()));
}

#[test]
fn hex_string_accepts_uppercase() {
    let upper = "A1B2C3D4E5F67890".to_string();
    let hex = HexString::new(upper).unwrap();
    assert_eq!(hex.expose_secret(), "a1b2c3d4e5f67890");
}

#[cfg(feature = "rand")]
#[test]
fn fixed_rng_into_inner() {
    let rng = FixedRng::<32>::generate();
    let fixed: Fixed<[u8; 32]> = rng.into_inner();
    assert_eq!(fixed.len(), 32);
}

#[cfg(feature = "rand")]
#[test]
fn fixed_rng_into_conversion() {
    let rng = FixedRng::<32>::generate();
    let fixed: Fixed<[u8; 32]> = rng.into();
    assert_eq!(fixed.len(), 32);
}

#[cfg(feature = "rand")]
#[test]
fn dynamic_rng_into_conversion() {
    let rng = DynamicRng::generate(64);
    let dynamic: Dynamic<Vec<u8>> = rng.into();
    assert_eq!(dynamic.len(), 64);
}

// ──────────────────────────────────────────────────────────────
// HexString validation edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn hex_string_empty_string() {
    let empty = "".to_string();
    let hex = HexString::new(empty).unwrap();
    assert_eq!(hex.expose_secret(), "");
    assert_eq!(hex.byte_len(), 0);
    assert_eq!(hex.to_bytes(), Vec::<u8>::new());
}

#[test]
fn hex_string_single_byte() {
    let single = "00".to_string();
    let hex = HexString::new(single).unwrap();
    assert_eq!(hex.expose_secret(), "00");
    assert_eq!(hex.byte_len(), 1);
    assert_eq!(hex.to_bytes(), vec![0u8]);
}

#[test]
fn hex_string_odd_length_rejected() {
    // Single character (odd length)
    let odd1 = "a".to_string();
    assert!(HexString::new(odd1).is_err());
    
    // Three characters (odd length)
    let odd3 = "abc".to_string();
    assert!(HexString::new(odd3).is_err());
    
    // Five characters (odd length)
    let odd5 = "abcde".to_string();
    assert!(HexString::new(odd5).is_err());
}

#[test]
fn hex_string_invalid_characters() {
    // Invalid character at beginning
    let invalid_start = "g1a2b3c4".to_string();
    assert!(HexString::new(invalid_start).is_err());
    
    // Invalid character in middle
    let invalid_middle = "a1b2z3c4".to_string();
    assert!(HexString::new(invalid_middle).is_err());
    
    // Invalid character at end
    let invalid_end = "a1b2c3x".to_string();
    assert!(HexString::new(invalid_end).is_err());
    
    // Multiple invalid characters
    let invalid_multi = "g1h2i3j4".to_string();
    assert!(HexString::new(invalid_multi).is_err());
    
    // Non-ASCII (should be rejected)
    let non_ascii = "a1b2ñ3c4".to_string();
    assert!(HexString::new(non_ascii).is_err());
}

#[test]
fn hex_string_mixed_case() {
    // Mixed uppercase and lowercase
    let mixed = "AaBbCcDdEeFf0123456789".to_string();
    let hex = HexString::new(mixed).unwrap();
    assert_eq!(hex.expose_secret(), "aabbccddeeff0123456789");
    // 22 hex characters = 11 bytes
    assert_eq!(hex.byte_len(), 11);
    assert_eq!(hex.expose_secret().len(), 22);
}

#[test]
fn hex_string_all_uppercase() {
    let upper = "ABCDEF0123456789".to_string();
    let hex = HexString::new(upper).unwrap();
    assert_eq!(hex.expose_secret(), "abcdef0123456789");
}

#[test]
fn hex_string_all_lowercase() {
    let lower = "abcdef0123456789".to_string();
    let hex = HexString::new(lower).unwrap();
    assert_eq!(hex.expose_secret(), "abcdef0123456789");
}

#[test]
fn hex_string_all_digits() {
    let digits = "0123456789abcdef".to_string();
    let hex = HexString::new(digits).unwrap();
    assert_eq!(hex.expose_secret(), "0123456789abcdef");
}

#[test]
fn hex_string_all_letters() {
    let letters = "abcdefABCDEF".to_string();
    let hex = HexString::new(letters).unwrap();
    assert_eq!(hex.expose_secret(), "abcdefabcdef");
}

#[test]
fn hex_string_very_long() {
    // 1KB of hex data (2048 hex chars = 1024 bytes)
    let long_hex = "a".repeat(2048);
    let hex = HexString::new(long_hex).unwrap();
    assert_eq!(hex.byte_len(), 1024);
    assert_eq!(hex.to_bytes().len(), 1024);
}

#[test]
fn hex_string_special_characters_rejected() {
    // Whitespace
    let with_space = "a1 b2 c3".to_string();
    assert!(HexString::new(with_space).is_err());
    
    let with_newline = "a1b2\nc3d4".to_string();
    assert!(HexString::new(with_newline).is_err());
    
    let with_tab = "a1b2\tc3d4".to_string();
    assert!(HexString::new(with_tab).is_err());
    
    // Special characters
    let with_dash = "a1-b2-c3".to_string();
    assert!(HexString::new(with_dash).is_err());
    
    let with_underscore = "a1_b2_c3".to_string();
    assert!(HexString::new(with_underscore).is_err());
}

// ──────────────────────────────────────────────────────────────
// Zeroization edge cases (when zeroize feature is enabled)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "zeroize")]
#[test]
fn hex_string_zeroization_on_odd_length() {
    // Create a string with known content
    let invalid = "secret123".to_string();
    
    // Attempt to create HexString (will fail due to odd length)
    let result = HexString::new(invalid);
    assert!(result.is_err());
    
    // The string should be zeroized (we can't directly check since it's moved,
    // but we can verify the error path was taken)
    // Note: We can't verify zeroization directly because the String is consumed,
    // but the code path is tested
}

#[cfg(feature = "zeroize")]
#[test]
fn hex_string_zeroization_on_invalid_chars() {
    // Create a string with known content and invalid characters
    let invalid = "secret123garbage".to_string();
    
    // Attempt to create HexString (will fail due to invalid chars)
    let result = HexString::new(invalid);
    assert!(result.is_err());
    
    // The string should be zeroized (same note as above)
}

#[cfg(not(feature = "zeroize"))]
#[test]
fn hex_string_no_zeroization_when_feature_disabled() {
    // When zeroize is disabled, zeroize_input is a no-op
    // This test just verifies the code path works
    let invalid = "a".to_string();
    assert!(HexString::new(invalid).is_err());
}

// ──────────────────────────────────────────────────────────────
// Conversion edge cases: Empty and single byte
// ──────────────────────────────────────────────────────────────

#[test]
fn to_hex_empty() {
    let empty: &[u8] = &[];
    assert_eq!(empty.to_hex(), "");
    assert_eq!(empty.to_hex_upper(), "");
}

#[test]
fn to_hex_single_byte() {
    let single: &[u8] = &[0x42];
    assert_eq!(single.to_hex(), "42");
    assert_eq!(single.to_hex_upper(), "42");
    
    let zero: &[u8] = &[0x00];
    assert_eq!(zero.to_hex(), "00");
    
    let max: &[u8] = &[0xFF];
    assert_eq!(max.to_hex(), "ff");
    assert_eq!(max.to_hex_upper(), "FF");
}

#[test]
fn to_hex_fixed_array_empty() {
    fixed_alias!(EmptyKey, 0);
    let key: EmptyKey = [].into();
    assert_eq!(key.expose_secret().to_hex(), "");
}

#[test]
fn to_hex_fixed_array_single() {
    fixed_alias!(SingleKey, 1);
    let key: SingleKey = [0xAB].into();
    assert_eq!(key.expose_secret().to_hex(), "ab");
    assert_eq!(key.expose_secret().to_hex_upper(), "AB");
}

#[test]
fn to_hex_all_zeros() {
    let zeros = vec![0u8; 32];
    assert_eq!(zeros.to_hex(), "0".repeat(64));
    assert_eq!(zeros.to_hex_upper(), "0".repeat(64));
}

#[test]
fn to_hex_all_ones() {
    let ones = vec![0xFFu8; 16];
    assert_eq!(ones.to_hex(), "f".repeat(32));
    assert_eq!(ones.to_hex_upper(), "F".repeat(32));
}

#[test]
fn to_hex_very_large() {
    // 1KB of data
    let large = vec![0x42u8; 1024];
    let hex = large.to_hex();
    assert_eq!(hex.len(), 2048); // 1024 bytes * 2 hex chars per byte
    assert_eq!(hex, "42".repeat(1024));
}

// ──────────────────────────────────────────────────────────────
// Base64url edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn to_base64url_empty() {
    let empty: &[u8] = &[];
    assert_eq!(empty.to_base64url(), "");
}

#[test]
fn to_base64url_single_byte() {
    let single: &[u8] = &[0x42];
    let b64 = single.to_base64url();
    assert!(!b64.is_empty());
    // Base64url encoding of single byte should be short
    assert!(b64.len() <= 4);
}

#[test]
fn to_base64url_all_zeros() {
    let zeros = vec![0u8; 32];
    let b64 = zeros.to_base64url();
    assert!(!b64.is_empty());
    // Should be URL-safe (no padding, no + or /)
    assert!(!b64.contains('+'));
    assert!(!b64.contains('/'));
    assert!(!b64.contains('='));
}

#[test]
fn to_base64url_all_ones() {
    let ones = vec![0xFFu8; 16];
    let b64 = ones.to_base64url();
    assert!(!b64.is_empty());
    assert!(!b64.contains('+'));
    assert!(!b64.contains('/'));
    assert!(!b64.contains('='));
}

#[test]
fn to_base64url_very_large() {
    // 1KB of data
    let large = vec![0x42u8; 1024];
    let b64 = large.to_base64url();
    assert!(!b64.is_empty());
    // Base64 encoding is ~4/3 the size of input
    assert!(b64.len() >= 1024);
    assert!(!b64.contains('+'));
    assert!(!b64.contains('/'));
    assert!(!b64.contains('='));
}

// ──────────────────────────────────────────────────────────────
// Constant-time equality edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn ct_eq_empty_slices() {
    let empty1: &[u8] = &[];
    let empty2: &[u8] = &[];
    assert!(empty1.ct_eq(empty2));
}

#[test]
fn ct_eq_single_byte() {
    let a: &[u8] = &[0x42];
    let b: &[u8] = &[0x42];
    let c: &[u8] = &[0x43];
    
    assert!(a.ct_eq(b));
    assert!(!a.ct_eq(c));
}

#[test]
fn ct_eq_different_lengths() {
    let short: &[u8] = &[0x42];
    let long: &[u8] = &[0x42, 0x43];
    
    assert!(!short.ct_eq(long));
    assert!(!long.ct_eq(short));
}

#[test]
fn ct_eq_all_zeros() {
    let zeros1 = vec![0u8; 32];
    let zeros2 = vec![0u8; 32];
    let ones = vec![0xFFu8; 32];
    
    assert!(zeros1.ct_eq(&zeros2));
    assert!(!zeros1.ct_eq(&ones));
}

#[test]
fn ct_eq_very_large() {
    let large1 = vec![0x42u8; 1024];
    let large2 = vec![0x42u8; 1024];
    let large3 = vec![0x43u8; 1024];
    
    assert!(large1.ct_eq(&large2));
    assert!(!large1.ct_eq(&large3));
}

#[test]
fn ct_eq_fixed_array_vs_slice() {
    fixed_alias!(Key32, 32);
    
    let key1: Key32 = [0x42u8; 32].into();
    let key2: Key32 = [0x42u8; 32].into();
    let key3: Key32 = [0x43u8; 32].into();
    
    // Fixed arrays can compare with each other
    assert!(key1.expose_secret().ct_eq(key2.expose_secret()));
    assert!(!key1.expose_secret().ct_eq(key3.expose_secret()));
    
    // Also test with slice conversion
    let slice1: &[u8] = key1.expose_secret().as_slice();
    let slice2: &[u8] = key2.expose_secret().as_slice();
    let slice3: &[u8] = key3.expose_secret().as_slice();
    
    assert!(slice1.ct_eq(slice2));
    assert!(!slice1.ct_eq(slice3));
}

#[test]
fn ct_eq_one_byte_different() {
    // Test that a single byte difference is detected
    let bytes1 = vec![0x42u8; 32];
    let mut bytes2 = vec![0x42u8; 32];
    bytes2[15] = 0x99;
    
    assert!(!bytes1.ct_eq(&bytes2));
}

#[test]
fn ct_eq_first_byte_different() {
    let bytes1 = vec![0x42u8; 32];
    let mut bytes2 = vec![0x42u8; 32];
    bytes2[0] = 0x99;
    
    assert!(!bytes1.ct_eq(&bytes2));
}

#[test]
fn ct_eq_last_byte_different() {
    let bytes1 = vec![0x42u8; 32];
    let mut bytes2 = vec![0x42u8; 32];
    bytes2[31] = 0x99;
    
    assert!(!bytes1.ct_eq(&bytes2));
}

// ──────────────────────────────────────────────────────────────
// HexString to_bytes edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn hex_string_to_bytes_empty() {
    let empty = "".to_string();
    let hex = HexString::new(empty).unwrap();
    assert_eq!(hex.to_bytes(), Vec::<u8>::new());
}

#[test]
fn hex_string_to_bytes_single_byte() {
    let single = "ff".to_string();
    let hex = HexString::new(single).unwrap();
    assert_eq!(hex.to_bytes(), vec![0xFFu8]);
}

#[test]
fn hex_string_to_bytes_all_values() {
    // Test all possible byte values (0x00 to 0xFF)
    let mut hex_chars = String::with_capacity(512);
    for i in 0u8..=255u8 {
        hex_chars.push_str(&format!("{:02x}", i));
    }
    
    let hex = HexString::new(hex_chars).unwrap();
    let bytes = hex.to_bytes();
    assert_eq!(bytes.len(), 256);
    
    for (i, &byte) in bytes.iter().enumerate() {
        assert_eq!(byte, i as u8);
    }
}

// ──────────────────────────────────────────────────────────────
// HexString equality edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn hex_string_eq_empty() {
    let empty1 = "".to_string();
    let empty2 = "".to_string();
    let hex1 = HexString::new(empty1).unwrap();
    let hex2 = HexString::new(empty2).unwrap();
    
    assert_eq!(hex1, hex2);
}

#[test]
fn hex_string_eq_same_content() {
    let s1 = "deadbeef".to_string();
    let s2 = "DEADBEEF".to_string(); // Different case
    let hex1 = HexString::new(s1).unwrap();
    let hex2 = HexString::new(s2).unwrap();
    
    // Should be equal because both normalize to lowercase
    assert_eq!(hex1, hex2);
}

#[test]
fn hex_string_ne_different_content() {
    let s1 = "deadbeef".to_string();
    let s2 = "cafebabe".to_string();
    let hex1 = HexString::new(s1).unwrap();
    let hex2 = HexString::new(s2).unwrap();
    
    assert_ne!(hex1, hex2);
}

// ──────────────────────────────────────────────────────────────
// RandomHex edge cases (when rand feature is enabled)
// ──────────────────────────────────────────────────────────────

#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn random_hex_different_each_time() {
    use secure_gate::RandomHex;
    
    let hex1: RandomHex = FixedRng::<32>::random_hex();
    let hex2: RandomHex = FixedRng::<32>::random_hex();
    
    // Should be different (extremely unlikely to be the same)
    assert_ne!(hex1.expose_secret(), hex2.expose_secret());
}

#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn random_hex_different_sizes() {
    use secure_gate::RandomHex;
    
    let hex16: RandomHex = FixedRng::<16>::random_hex();
    let hex32: RandomHex = FixedRng::<32>::random_hex();
    let hex64: RandomHex = FixedRng::<64>::random_hex();
    
    assert_eq!(hex16.byte_len(), 16);
    assert_eq!(hex32.byte_len(), 32);
    assert_eq!(hex64.byte_len(), 64);
    
    assert_eq!(hex16.expose_secret().len(), 32); // 16 bytes = 32 hex chars
    assert_eq!(hex32.expose_secret().len(), 64); // 32 bytes = 64 hex chars
    assert_eq!(hex64.expose_secret().len(), 128); // 64 bytes = 128 hex chars
}

#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn random_hex_valid_format() {
    use secure_gate::RandomHex;
    
    let hex: RandomHex = FixedRng::<32>::random_hex();
    
    // Should be all lowercase hex
    assert!(hex.expose_secret().chars().all(|c| c.is_ascii_hexdigit()));
    assert!(hex.expose_secret().chars().all(|c| !c.is_uppercase()));
    
    // Should decode correctly
    let bytes = hex.to_bytes();
    assert_eq!(bytes.len(), 32);
}

// ──────────────────────────────────────────────────────────────
// Fixed array conversions edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_array_to_hex() {
    fixed_alias!(Key16, 16);
    fixed_alias!(Key32, 32);
    
    let k16: Key16 = [0x42u8; 16].into();
    let k32: Key32 = [0xABu8; 32].into();
    
    assert_eq!(k16.expose_secret().to_hex(), "42".repeat(16));
    assert_eq!(k32.expose_secret().to_hex(), "ab".repeat(32));
}

#[test]
fn fixed_array_to_base64url() {
    fixed_alias!(Key32, 32);
    
    let k: Key32 = [0x42u8; 32].into();
    let b64 = k.expose_secret().to_base64url();
    
    assert!(!b64.is_empty());
    assert!(!b64.contains('+'));
    assert!(!b64.contains('/'));
    assert!(!b64.contains('='));
}

#[test]
fn fixed_array_ct_eq() {
    fixed_alias!(Key32, 32);
    
    let k1: Key32 = [0x42u8; 32].into();
    let k2: Key32 = [0x42u8; 32].into();
    let k3: Key32 = [0x43u8; 32].into();
    
    assert!(k1.expose_secret().ct_eq(k2.expose_secret()));
    assert!(!k1.expose_secret().ct_eq(k3.expose_secret()));
}

