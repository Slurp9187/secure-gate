// ==========================================================================
// tests/conversions_tests.rs
// ==========================================================================
#![cfg(feature = "conversions")]

use secure_gate::{dynamic_alias, HexString, SecureConversionsExt};
// No more SecureConversionsExt import — we use it on the exposed secret

#[cfg(feature = "rand")]
use secure_gate::{
    rng::{DynamicRng, FixedRng},
    Dynamic, Fixed,
};

#[cfg(all(feature = "rand", feature = "conversions"))]
use secure_gate::RandomHex;

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

#[test]
fn base64string_validation_stricter() {
    // Test valid cases - these should all decode successfully

    // Test valid cases - these should all decode successfully
    let valid_cases = vec![
        ("", 0),              // Empty string
        ("SGVs", 3),          // 4 chars -> 3 bytes ("Hel")
        ("SGVsbG8", 5),       // 7 chars -> 5 bytes ("Hello")
        ("SGVsbG93b3JsZA", 10), // 14 chars -> 10 bytes
        ("_3zVf4OlpW3Cxy_QPqDg8KGyw9Tl9gcYKTpLXG1-j5A", 32), // 43 chars -> 32 bytes
    ];

    for (input, expected_bytes) in valid_cases {
        let b64 = secure_gate::conversions::Base64String::new(input.to_string())
            .expect(&format!("'{}' should be valid", input));
        assert_eq!(b64.expose_secret(), input);
        let bytes = b64.to_bytes();
        assert_eq!(bytes.len(), expected_bytes, "Wrong byte length for '{}'", input);
    }

    // Test invalid cases - these should be rejected
    let invalid_cases = vec![
        "S",           // 1 char - 6-bit remainder
        "SG",          // 2 chars - invalid last symbol
        "SGV",         // 3 chars - invalid last symbol
        "SGVsb",       // 5 chars - 6-bit remainder
        "SGVsbG",      // 6 chars - invalid last symbol
        "SGVsbG8=",    // Contains padding
        "SGVsbG8!",    // Invalid character
        "SGVsbG8\n",   // Invalid character (newline)
        "SGVsbG8\t",   // Invalid character (tab)
        "SGVsbG8 ",    // Invalid character (space)
    ];

    for input in invalid_cases {
        let result = secure_gate::conversions::Base64String::new(input.to_string());
        assert!(result.is_err(), "'{}' should be invalid but was accepted", input);
    }

    // Based on the above, valid lengths are those that can actually be decoded
    // It seems like any length is potentially valid as long as the base64 decoding succeeds
    // But that would require actually trying to decode, which defeats the purpose of validation

    // Actually, let me check what the base64 crate documentation says about no-pad...
    // For no-pad, it seems lengths that are not multiples of 4 can still be valid
    // Let me adjust the validation to actually try decoding instead of length check

    // Wait, but that would be expensive. Let me see if there's a pattern.
    // From the output above:
    // len%4 == 0: can be valid or invalid
    // len%4 == 1: invalid (6-bit remainder)
    // len%4 == 2: invalid (last symbol issues)
    // len%4 == 3: invalid (last symbol issues)
    // But "SGVsbG8" (len=7, 7%4=3) decoded successfully!

    // Let me check the base64 crate source or documentation...
    // Actually, for URL_SAFE_NO_PAD, it allows lengths that are not multiples of 4
    // as long as the last group can be properly decoded.

    // So my length check was wrong. Let me remove it and just check characters.
    // But then how do I prevent the panic? The audit says to_bytes() will panic if invalid.
    // Maybe I need to actually try decoding in validation?

    // Actually, let me check what happens if I try to decode during validation.
    // That might be the right approach - do the character check first (fast), then try decode.
}