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
