// secure-gate/tests/random/dynamic_rng_tests.rs
// Tests specific to DynamicRng functionality.

#![cfg(feature = "rand")]

use secure_gate::random::DynamicRng;

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

#[cfg(feature = "encoding-hex")]
#[test]
fn dynamic_rng_hex() {
    let rng = DynamicRng::generate(64);
    let hex = rng.to_hex();
    assert_eq!(hex.byte_len(), 64);

    let rng2 = DynamicRng::generate(64);
    let owned = rng2.into_hex();
    assert_eq!(owned.decode_secret_to_bytes().len(), 64);
}
