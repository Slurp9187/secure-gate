// tests/rng_correctness_tests.rs
// Exhaustive tests for random-only types and aliases

#![cfg(feature = "rand")]

use secure_gate::{
    fixed_alias_rng,
    random::{DynamicRng, FixedRng},
};

#[test]
fn basic_generation() {
    fixed_alias_rng!(Key32, 32);

    let a = Key32::generate();
    let b = Key32::generate();

    assert_ne!(a.expose_secret(), b.expose_secret());
    assert!(!a.expose_secret().iter().all(|&b| b == 0));
    assert_eq!(a.len(), 32);
}

#[test]
fn debug_is_redacted() {
    fixed_alias_rng!(DebugTest, 32);
    let rb = DebugTest::generate();
    assert_eq!(format!("{rb:?}"), "[REDACTED]");
}

#[test]
fn different_aliases_are_different_types() {
    fixed_alias_rng!(TypeA, 32);
    fixed_alias_rng!(TypeB, 32);
    let a = TypeA::generate();
    let _ = a;
    // let _wrong: TypeB = a; // must not compile
}

#[test]
fn raw_fixed_rng_works() {
    let a = FixedRng::<32>::generate();
    let b = FixedRng::<32>::generate();
    assert_ne!(a.expose_secret(), b.expose_secret());
    assert_eq!(a.len(), 32);
}

#[test]
fn zero_length_works() {
    let zero = FixedRng::<0>::generate();
    assert!(zero.is_empty());
    assert_eq!(zero.len(), 0);

    let dyn_zero = DynamicRng::generate(0);
    assert!(dyn_zero.is_empty());
    assert_eq!(dyn_zero.len(), 0);
}

// ct_eq returns false for different lengths (no panic)
#[cfg(feature = "ct-eq")]
#[test]
fn ct_eq_different_lengths() {
    let a = DynamicRng::generate(32);
    let b = DynamicRng::generate(64);

    // Access the inner Dynamic<Vec<u8>> via into_inner() — safe in test
    let a_inner: secure_gate::Dynamic<Vec<u8>> = a.into_inner();
    let b_inner: secure_gate::Dynamic<Vec<u8>> = b.into_inner();

    assert!(!a_inner.ct_eq(&b_inner));
}

#[cfg(feature = "zeroize")]
#[test]
fn zeroize_trait_is_available() {
    use secure_gate::Fixed;
    use zeroize::Zeroize;
    let mut key = Fixed::<[u8; 32]>::new([0xFF; 32]);
    key.zeroize();
    assert_eq!(key.expose_secret(), &[0u8; 32]);
}

#[test]
fn try_generate_success() {
    // Test try_generate variants work without errors
    let fixed: FixedRng<16> = FixedRng::try_generate().unwrap();
    assert_eq!(fixed.len(), 16);

    let dynamic: DynamicRng = DynamicRng::try_generate(32).unwrap();
    assert_eq!(dynamic.len(), 32);
}

#[test]
fn into_inner_and_conversions() {
    // Test into_inner preserves data without exposing
    let fixed_rng = FixedRng::<8>::generate();
    let fixed_inner: secure_gate::Fixed<[u8; 8]> = fixed_rng.into_inner();
    assert_eq!(fixed_inner.len(), 8);

    // Test From conversion
    let fixed_rng2 = FixedRng::<8>::generate();
    let fixed_converted: secure_gate::Fixed<[u8; 8]> = fixed_rng2.into();
    assert_eq!(fixed_converted.len(), 8);

    let dynamic_rng = DynamicRng::generate(16);
    let dynamic_inner: secure_gate::Dynamic<Vec<u8>> = dynamic_rng.into_inner();
    assert_eq!(dynamic_inner.len(), 16);

    // Test From conversion for dynamic
    let dynamic_rng2 = DynamicRng::generate(16);
    let dynamic_converted: secure_gate::Dynamic<Vec<u8>> = dynamic_rng2.into();
    assert_eq!(dynamic_converted.len(), 16);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hex_methods_work() {
    // Test to_hex (non-consuming)
    let rng = FixedRng::<4>::generate();
    let hex = rng.to_hex();
    assert_eq!(hex.byte_len(), 4);
    assert!(hex.expose_secret().chars().all(|c| c.is_ascii_hexdigit()));

    // Test into_hex (consuming)
    let rng2 = FixedRng::<4>::generate();
    let owned_hex = rng2.into_hex();
    assert_eq!(owned_hex.byte_len(), 4);
    assert!(owned_hex
        .expose_secret()
        .chars()
        .all(|c| c.is_ascii_hexdigit()));

    // Basic round-trip check (hex decodes back)
    let bytes = owned_hex.decode_secret_to_bytes();
    assert_eq!(bytes.len(), 4);
}

#[cfg(all(feature = "rand", feature = "encoding-base64"))]
#[test]
fn base64_roundtrip() {
    let rng = FixedRng::<32>::generate();
    let encoded = rng.to_base64();
    assert_eq!(
        encoded.decode_secret_to_bytes(),
        rng.expose_secret().to_vec()
    );
}

#[cfg(all(feature = "rand", feature = "encoding-base64"))]
#[test]
fn base64_methods_work() {
    // Test to_base64 (non-consuming)
    let rng = FixedRng::<4>::generate();
    let base64 = rng.to_base64();
    assert_eq!(base64.byte_len(), 4);
    // Valid URL-safe base64 chars
    assert!(base64
        .expose_secret()
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

    // Test into_base64 (consuming)
    let rng2 = FixedRng::<4>::generate();
    let owned_base64 = rng2.into_base64();
    assert_eq!(owned_base64.byte_len(), 4);
    assert!(owned_base64
        .expose_secret()
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

    // Basic round-trip check (base64 decodes back)
    let bytes = owned_base64.decode_secret_to_bytes();
    assert_eq!(bytes.len(), 4);
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
#[test]
fn bech32_variants_roundtrip() {
    let rng = FixedRng::<32>::generate();
    let b32 = rng.to_bech32("test");
    assert!(b32.is_bech32());
    assert_eq!(b32.decode_secret_to_bytes(), rng.expose_secret().to_vec());

    let b32m = rng.to_bech32m("test");
    assert!(b32m.is_bech32m());
    assert_eq!(b32m.decode_secret_to_bytes(), rng.expose_secret().to_vec());
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
#[test]
fn bech32_methods_work() {
    // Test various sizes
    let rng16 = FixedRng::<16>::generate();
    let b32_16 = rng16.to_bech32("example");
    assert!(b32_16.is_bech32());
    assert_eq!(b32_16.decode_secret_to_bytes().len(), 16);

    let b32m_16 = rng16.to_bech32m("example");
    assert!(b32m_16.is_bech32m());
    assert_eq!(b32m_16.decode_secret_to_bytes().len(), 16);

    // Test into_* (consuming)
    let rng32 = FixedRng::<32>::generate();
    let owned_b32 = rng32.into_bech32("hrp");
    assert!(owned_b32.is_bech32());
    assert_eq!(owned_b32.decode_secret_to_bytes().len(), 32);

    let rng32m = FixedRng::<32>::generate();
    let owned_b32m = rng32m.into_bech32m("hrp");
    assert!(owned_b32m.is_bech32m());
    assert_eq!(owned_b32m.decode_secret_to_bytes().len(), 32);
}

#[cfg(all(feature = "rand", feature = "encoding-base64"))]
#[test]
fn dynamic_rng_base64() {
    let rng = DynamicRng::generate(64);
    let encoded = rng.to_base64();
    assert_eq!(
        encoded.decode_secret_to_bytes(),
        rng.expose_secret().to_vec()
    );

    let rng2 = DynamicRng::generate(64);
    let owned = rng2.into_base64();
    assert_eq!(owned.decode_secret_to_bytes().len(), 64);
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
#[test]
fn dynamic_rng_bech32() {
    let rng = DynamicRng::generate(64);
    let b32 = rng.to_bech32("test");
    assert!(b32.is_bech32());
    assert_eq!(b32.decode_secret_to_bytes(), rng.expose_secret().to_vec());

    let rng2 = DynamicRng::generate(64);
    let b32m = rng2.to_bech32m("test");
    assert!(b32m.is_bech32m());
    assert_eq!(b32m.decode_secret_to_bytes(), rng2.expose_secret().to_vec());

    // into_* consuming
    let rng3 = DynamicRng::generate(32);
    let owned_b32 = rng3.into_bech32("hrp");
    assert_eq!(owned_b32.decode_secret_to_bytes().len(), 32);
}

#[cfg(all(feature = "rand", feature = "encoding-hex"))]
#[test]
fn dynamic_rng_hex() {
    let rng = DynamicRng::generate(64);
    let hex = rng.to_hex();
    assert_eq!(hex.byte_len(), 64);

    let rng2 = DynamicRng::generate(64);
    let owned = rng2.into_hex();
    assert_eq!(owned.decode_secret_to_bytes().len(), 64);
}
