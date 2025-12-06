// tests/conversions_tests.rs
//! Tests for the optional `conversions` feature
//!
//! Only compiled when the `conversions` feature is enabled.

#![cfg(feature = "conversions")]

use secure_gate::{fixed_alias, SecureConversionsExt};

fixed_alias!(TestKey, 32);
fixed_alias!(Nonce, 24);
fixed_alias!(SmallKey, 16);

#[test]
fn to_hex_and_to_hex_upper() {
    let bytes = [
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
    let key = TestKey::from([
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
    let key1 = TestKey::from([1u8; 32]);
    let key2 = TestKey::from([1u8; 32]);

    assert!(key1.expose_secret().ct_eq(key2.expose_secret()));
}

#[test]
fn ct_eq_different_keys() {
    let key1 = TestKey::from([1u8; 32]);
    let key2 = TestKey::from([2u8; 32]);

    let mut bytes = [1u8; 32];
    bytes[31] = 9;
    let key3 = TestKey::from(bytes);

    assert!(!key1.expose_secret().ct_eq(key2.expose_secret()));
    assert!(!key1.expose_secret().ct_eq(key3.expose_secret()));
}

#[test]
fn works_on_all_fixed_alias_sizes() {
    let nonce: Nonce = [0xFFu8; 24].into();
    let small: SmallKey = [0xAAu8; 16].into();

    assert_eq!(nonce.expose_secret().to_hex().len(), 48);
    assert_eq!(small.expose_secret().to_hex().len(), 32);

    assert_eq!(nonce.expose_secret().to_base64url().len(), 32);
    assert_eq!(small.expose_secret().to_base64url().len(), 22);
}

#[test]
fn trait_is_available_on_fixed_alias_types() {
    fixed_alias!(MyKey, 32);

    let key = MyKey::from([0x42u8; 32]);

    let _ = key.expose_secret().to_hex();
    let _ = key.expose_secret().to_base64url();
    let _ = key.expose_secret().ct_eq(key.expose_secret());
}

#[cfg(feature = "conversions")]
#[test]
fn hex_string_validates_and_decodes() {
    use secure_gate::HexString;
    let valid = "a1b2c3d4e5f67890".to_string(); // 16 chars (8 bytes)
    let hex = HexString::new(valid).unwrap();
    assert_eq!(hex.expose_secret(), "a1b2c3d4e5f67890");
    assert_eq!(hex.byte_len(), 8);
    assert_eq!(
        hex.to_bytes(),
        vec![0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78, 0x90]
    );

    let invalid = "a1b2c3d".to_string(); // Odd length
    assert!(HexString::new(invalid).is_err());
}

#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn random_hex_returns_randomhex() {
    use secure_gate::fixed_alias_rng;

    fixed_alias_rng!(HexKey, 32);

    let hex: secure_gate::RandomHex = HexKey::random_hex();

    assert_eq!(hex.expose_secret().len(), 64);
    assert!(hex.expose_secret().chars().all(|c| c.is_ascii_hexdigit()));

    let bytes_back = hex.to_bytes();
    assert_eq!(bytes_back.len(), 32);
}
