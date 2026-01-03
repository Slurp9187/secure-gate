// ==========================================================================
// tests/macros_correctness_tests.rs
// ==========================================================================
// Exhaustive tests for macro correctness and safety

#![cfg(test)]

use secure_gate::{dynamic_alias, fixed_alias};

// Only import RNG-related items when the `rand` feature is enabled
#[cfg(feature = "rand")]
use secure_gate::{
    fixed_alias_rng,
    random::{DynamicRng, FixedRng},
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

#[test]
fn non_zero_size_validation() {
    // Valid minimal size
    fixed_alias!(MinimalKey, 1);
    let k: MinimalKey = [42u8].into();
    assert_eq!(k.len(), 1);

    #[cfg(feature = "rand")]
    {
        fixed_alias_rng!(MinimalRngKey, 1);
        let rk = MinimalRngKey::generate();
        assert_eq!(rk.len(), 1);
        assert_ne!(*rk.expose_secret(), [0u8; 1]); // Not zeroed
    }

    // Compile-fail test: Uncomment to verify (should fail build)
    // fixed_alias!(ZeroKey, 0);  // Expected: Compile error
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

    let k1 = Aes256Key::generate();
    let k2 = Aes256Key::generate();
    assert_ne!(k1.expose_secret(), k2.expose_secret());
    assert_eq!(k1.len(), 32);

    let n1 = Nonce::generate();
    assert_eq!(n1.len(), 24);
    assert_ne!(*n1.expose_secret(), [0u8; 24]);
}

// ──────────────────────────────────────────────────────────────
// Raw RNG types work directly (requires "rand")
// ──────────────────────────────────────────────────────────────
#[cfg(feature = "rand")]
#[test]
fn raw_rng_types_work() {
    // Fixed-size
    let a = FixedRng::<16>::generate();
    let b = FixedRng::<16>::generate();
    assert_ne!(a.expose_secret(), b.expose_secret());

    // Dynamic — length must be specified
    let c = DynamicRng::generate(64);
    assert_eq!(c.expose_secret().len(), 64);

    // Using a type alias (preferred style)
    type MyToken = DynamicRng;
    let d = MyToken::generate(128);
    assert_eq!(d.expose_secret().len(), 128);
}
