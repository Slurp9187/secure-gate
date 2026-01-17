// secure-gate/tests/random/dynamic_random_tests.rs
// Tests specific to DynamicRandom functionality.

#![cfg(feature = "rand")]

#[allow(unused_imports)]
use secure_gate::random::DynamicRandom;
use secure_gate::ExposeSecret;
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
use secure_gate::SecureEncodingExt;

#[cfg(feature = "ct-eq")]
#[test]
fn ct_eq_different_lengths() {
    let a = DynamicRandom::generate(32);
    let b = DynamicRandom::generate(64);

    // Access the inner Dynamic<Vec<u8>> via into_inner() — safe in test
    let a_inner: secure_gate::Dynamic<Vec<u8>> = a.into_inner();
    let b_inner: secure_gate::Dynamic<Vec<u8>> = b.into_inner();

    assert!(!a_inner.ct_eq(&b_inner));
}

#[cfg(all(feature = "rand", feature = "encoding-base64"))]
#[test]
fn dynamic_random_base64() {
    let rng = DynamicRandom::generate(64);
    let encoded = rng.expose_secret().to_base64url();
    assert_eq!(encoded.into_bytes(), rng.expose_secret().to_vec());

    let rng2 = DynamicRandom::generate(64);
    let owned = rng2.into_base64url();
    assert_eq!(owned.into_bytes().len(), 64);
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
#[test]
fn dynamic_random_bech32() {
    let rng = DynamicRandom::generate(64);
    let b32 = rng.expose_secret().try_to_bech32("test").unwrap();
    assert!(b32.is_bech32());
    assert_eq!(b32.into_bytes(), rng.expose_secret().to_vec());

    let rng2 = DynamicRandom::generate(64);
    let b32m = rng2.expose_secret().try_to_bech32m("test").unwrap();
    assert_eq!(b32m.into_bytes(), rng2.expose_secret().to_vec());

    // into_* consuming
    let rng3 = DynamicRandom::generate(32);
    let owned_b32 = rng3.try_into_bech32("hrp").unwrap();
    assert!(owned_b32.is_bech32());
    assert_eq!(owned_b32.into_bytes().len(), 32);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn dynamic_random_hex() {
    let rng = DynamicRandom::generate(64);
    let hex = rng.expose_secret().to_hex();
    assert_eq!(hex.byte_len(), 64);

    let rng2 = DynamicRandom::generate(64);
    let owned = rng2.into_hex();
    assert_eq!(owned.into_bytes().len(), 64);
}
