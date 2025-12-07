// tests/rng_correctness_tests.rs
// Exhaustive tests for random-only types and aliases

#![cfg(feature = "rand")]

use secure_gate::{
    fixed_alias_rng,
    rng::{DynamicRng, FixedRng},
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
#[cfg(feature = "conversions")]
#[test]
fn ct_eq_different_lengths() {
    use secure_gate::SecureConversionsExt;

    let a = DynamicRng::generate(32);
    let b = DynamicRng::generate(64);

    // Access the inner Dynamic<Vec<u8>> via into_inner() — safe in test
    let a_inner: secure_gate::Dynamic<Vec<u8>> = a.into_inner();
    let b_inner: secure_gate::Dynamic<Vec<u8>> = b.into_inner();

    assert!(!a_inner.expose_secret().ct_eq(b_inner.expose_secret()));
}

#[test]
#[cfg(feature = "zeroize")]
fn zeroize_trait_is_available() {
    use secure_gate::Fixed;
    use zeroize::Zeroize;
    let mut key = Fixed::<[u8; 32]>::new([0xFF; 32]);
    key.zeroize();
    assert_eq!(key.expose_secret(), &[0u8; 32]);
}
