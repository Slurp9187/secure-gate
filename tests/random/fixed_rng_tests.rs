// secure-gate/tests/random/fixed_rng_tests.rs
// Tests specific to FixedRng functionality.

#![cfg(feature = "rand")]

use secure_gate::encoding::{base64::Base64String, hex::HexString};
use secure_gate::random::FixedRng;
use secure_gate::SecureEncodingExt;

#[test]
fn raw_fixed_rng_works() {
    let a = FixedRng::<32>::generate();
    let b = FixedRng::<32>::generate();
    assert_ne!(a.expose_secret(), b.expose_secret());
    assert_eq!(a.len(), 32);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hex_methods_work() {
    // Test to_hex (non-consuming)
    let rng = FixedRng::<4>::generate();
    let hex = HexString::new(rng.expose_secret().to_hex()).unwrap();
    assert_eq!(hex.byte_len(), 4);
    assert!(hex
        .expose_secret()
        .chars()
        .all(|c: char| c.is_ascii_hexdigit()));

    // Test into_hex (consuming)
    let rng2 = FixedRng::<4>::generate();
    let owned_hex = rng2.into_hex();
    assert_eq!(owned_hex.byte_len(), 4);
    assert!(owned_hex
        .expose_secret()
        .chars()
        .all(|c| c.is_ascii_hexdigit()));

    // Basic round-trip check (hex decodes back)
    let bytes = owned_hex.into_bytes();
    assert_eq!(bytes.len(), 4);
}

#[cfg(all(feature = "rand", feature = "encoding-base64"))]
#[test]
fn base64_roundtrip() {
    let rng = FixedRng::<32>::generate();
    let encoded = Base64String::new(rng.expose_secret().to_base64url()).unwrap();
    assert_eq!(
        encoded.expose_secret().to_bytes(),
        rng.expose_secret().to_vec()
    );
}

#[cfg(all(feature = "rand", feature = "encoding-base64"))]
#[test]
fn base64_methods_work() {
    // Test to_base64 (non-consuming)
    let rng = FixedRng::<4>::generate();
    let base64 = Base64String::new(rng.expose_secret().to_base64url()).unwrap();
    assert_eq!(base64.byte_len(), 4);
    // Valid URL-safe base64 chars
    assert!(base64
        .expose_secret()
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

    // Test into_base64 (consuming)
    let rng2 = FixedRng::<4>::generate();
    let owned_base64 = rng2.into_base64();
    assert_eq!(owned_base64.byte_len(), 4);
    assert!(owned_base64
        .expose_secret()
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

    // Basic round-trip check (base64 decodes back)
    let bytes = owned_base64.into_bytes();
    assert_eq!(bytes.len(), 4);
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
#[test]
fn bech32_variants_roundtrip() {
    let rng = FixedRng::<32>::generate();
    let b32 = rng.expose_secret().to_bech32("test");
    assert!(b32.is_bech32());
    assert_eq!(b32.expose_secret().to_bytes(), rng.expose_secret().to_vec());

    let b32m = rng.expose_secret().to_bech32m("test");
    assert!(b32m.is_bech32m());
    assert_eq!(
        b32m.expose_secret().to_bytes(),
        rng.expose_secret().to_vec()
    );
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
#[test]
fn bech32_methods_work() {
    // Test various sizes
    let rng16 = FixedRng::<16>::generate();
    let b32_16 = rng16.expose_secret().to_bech32("example");
    assert!(b32_16.is_bech32());
    assert_eq!(b32_16.into_bytes().len(), 16);

    let b32m_16 = rng16.expose_secret().to_bech32m("example");
    assert!(b32m_16.is_bech32m());
    assert_eq!(b32m_16.into_bytes().len(), 16);

    // Test into_* (consuming)
    let rng32 = FixedRng::<32>::generate();
    let owned_b32 = rng32.into_bech32("hrp");
    assert!(owned_b32.is_bech32());
    assert_eq!(owned_b32.into_bytes().len(), 32);

    let rng32m = FixedRng::<32>::generate();
    let owned_b32m = rng32m.into_bech32m("hrp");
    assert!(owned_b32m.is_bech32m());
    assert_eq!(owned_b32m.into_bytes().len(), 32);
}
