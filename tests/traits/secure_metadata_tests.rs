//! Tests for metadata access on secret wrappers.
//!
//! Since SecureMetadata was merged into ExposeSecret, these tests verify
//! that `len()` and `is_empty()` work on various secret types.

#[allow(unused_imports)]
use secure_gate::ExposeSecret;

#[cfg(feature = "rand")]
use secure_gate::random::{DynamicRandom, FixedRandom};

#[cfg(feature = "encoding-hex")]
use secure_gate::encoding::hex::HexString;

#[cfg(feature = "encoding-base64")]
use secure_gate::encoding::base64::Base64String;

#[cfg(feature = "encoding-bech32")]
use secure_gate::encoding::bech32::Bech32String;

#[test]
fn test_fixed_metadata() {
    let secret: secure_gate::Fixed<[u8; 32]> = secure_gate::Fixed::new([1u8; 32]);
    assert_eq!(secret.len(), 32);
    assert!(!secret.is_empty());

    let empty: secure_gate::Fixed<[u8; 0]> = secure_gate::Fixed::new([]);
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}

#[test]
fn test_dynamic_string_metadata() {
    let secret: secure_gate::Dynamic<String> = secure_gate::Dynamic::new("hello".to_string());
    assert_eq!(secret.len(), 5);
    assert!(!secret.is_empty());
}

#[test]
fn test_dynamic_vec_metadata() {
    let secret: secure_gate::Dynamic<Vec<u8>> = secure_gate::Dynamic::new(vec![1u8, 2, 3]);
    assert_eq!(secret.len(), 3);
    assert!(!secret.is_empty());
}

#[cfg(feature = "rand")]
#[test]
fn test_random_metadata() {
    let fixed = FixedRandom::<32>::generate();
    assert_eq!(fixed.len(), 32);

    let dynamic = DynamicRandom::generate(64);
    assert_eq!(dynamic.len(), 64);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_hex_metadata() {
    let secret = HexString::new("deadbeef".to_string()).unwrap();
    assert_eq!(secret.len(), 8);
    assert!(!secret.is_empty());
}

#[cfg(feature = "encoding-base64")]
#[test]
fn test_base64_metadata() {
    let secret = Base64String::new("SGVsbG8".to_string()).unwrap();
    assert_eq!(secret.len(), 7);
    assert!(!secret.is_empty());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_bech32_metadata() {
    let secret =
        Bech32String::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string()).unwrap();
    assert_eq!(secret.len(), 42);
    assert!(!secret.is_empty());
}
