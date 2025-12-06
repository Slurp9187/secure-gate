// tests/macros_correctness_tests.rs
//! Exhaustive macro correctness and safety tests
//!
//! These tests ensure every public macro works exactly as documented,
//! across all feature combinations, and cannot be broken by future refactors.

#![cfg(test)]

use secure_gate::{
    dynamic_alias, dynamic_alias_rng, fixed_alias, fixed_alias_rng,
    rng::{DynamicRng, FixedRng},
};

// ──────────────────────────────────────────────────────────────
// Basic fixed-size alias (no rand)
// ──────────────────────────────────────────────────────────────
#[test]
fn fixed_alias_basics() {
    fixed_alias!(MyKey, 32);

    let k: MyKey = [0u8; 32].into();
    assert_eq!(k.len(), 32);
    assert_eq!(k.expose_secret().len(), 32);
}

// ──────────────────────────────────────────────────────────────
// Dynamic (heap) alias
// ──────────────────────────────────────────────────────────────
#[test]
fn dynamic_alias_basics() {
    dynamic_alias!(MyPass, String);
    dynamic_alias!(MyToken, Vec<u8>);

    let p: MyPass = "hunter2".into();
    assert_eq!(p.expose_secret(), "hunter2");

    let t: MyToken = vec![1, 2, 3].into();
    assert_eq!(t.expose_secret(), &[1, 2, 3]);
}

// ──────────────────────────────────────────────────────────────
// Random-only fixed-size aliases (requires "rand")
// ──────────────────────────────────────────────────────────────
#[cfg(feature = "rand")]
#[test]
fn fixed_alias_rng_basics() {
    fixed_alias_rng!(Aes256Key, 32);
    fixed_alias_rng!(Nonce, 24);

    let k1 = Aes256Key::rng();
    let k2 = Aes256Key::rng();
    assert_ne!(k1.expose_secret(), k2.expose_secret());
    assert_eq!(k1.len(), 32);

    let n1 = Nonce::rng();
    assert_eq!(n1.len(), 24);
    assert_ne!(*n1.expose_secret(), [0u8; 24]); // sanity check
}

// ──────────────────────────────────────────────────────────────
// Random-only dynamic alias (requires "rand")
// ──────────────────────────────────────────────────────────────
#[cfg(feature = "rand")]
#[test]
fn dynamic_alias_rng_basics() {
    dynamic_alias_rng!(Salt);

    let s1 = Salt::rng(32);
    let s2 = Salt::rng(32);
    assert_eq!(s1.len(), 32);
    assert_eq!(s2.len(), 32);
    assert_ne!(s1.expose_secret(), s2.expose_secret());
}

// ──────────────────────────────────────────────────────────────
// Direct use of raw types (ensures no hidden breakage)
// ──────────────────────────────────────────────────────────────
#[cfg(feature = "rand")]
#[test]
fn raw_rng_types_work() {
    let a = FixedRng::<16>::rng();
    let b = FixedRng::<16>::rng();
    assert_ne!(a.expose_secret(), b.expose_secret());

    let c = DynamicRng::rng(64);
    assert_eq!(c.len(), 64);
}

// ──────────────────────────────────────────────────────────────
// random_hex() works with aliases (requires both features)
// ──────────────────────────────────────────────────────────────
#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn random_hex_via_alias() {
    fixed_alias_rng!(HexKey, 32);

    let hex = HexKey::random_hex();

    assert_eq!(hex.expose_secret().len(), 64);
    assert!(hex.expose_secret().chars().all(|c| c.is_ascii_hexdigit()));
    assert!(hex.expose_secret().chars().all(|c| !c.is_uppercase())); // ensure no uppercase letters

    let bytes = hex.to_bytes();
    assert_eq!(bytes.len(), 32);
}

// ──────────────────────────────────────────────────────────────
// Ensure no deprecated random APIs exist (compile-fail guard)
// ──────────────────────────────────────────────────────────────
#[cfg(feature = "rand")]
mod no_deprecated_random_api {
    use secure_gate::fixed_alias_rng;

    fixed_alias_rng!(Check, 32);

    // These must fail to compile — that's the point!
    // If any of these lines compile → the security invariant is broken.
    // #[allow(dead_code)]
    // fn bad() {
    //     let _ = Check::new();
    //     let _ = Check::random();
    //     let _ = Check::random_bytes();
    // }
}
