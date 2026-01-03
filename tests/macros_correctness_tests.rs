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

// ──────────────────────────────────────────────────────────────
// random_hex() works with aliases (requires both features)
// ──────────────────────────────────────────────────────────────
#[cfg(all(feature = "rand", feature = "encoding-hex"))]
#[test]
fn into_hex_via_alias() {
    fixed_alias_rng!(HexKey, 32);

    let hex = HexKey::generate().into_hex();

    assert_eq!(hex.expose_secret().len(), 64);
    assert!(hex
        .expose_secret()
        .chars()
        .all(|c: char| c.is_ascii_hexdigit()));
    assert!(hex.expose_secret().chars().all(|c: char| !c.is_uppercase()));

    let bytes = hex.to_bytes();
    assert_eq!(bytes.len(), 32);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_new_rejects_invalid() {
    use secure_gate::HexString;

    let s = "invalid hex".to_string(); // odd length
    let err = HexString::new(s).unwrap_err();
    assert_eq!(err, "invalid hex string");

    let s = "g".to_string(); // invalid digit
    let err = HexString::new(s).unwrap_err();
    assert_eq!(err, "invalid hex string");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hexstring_new_in_place_lowercase() {
    use secure_gate::HexString;

    let s = "DEADBEEF".to_string();
    let hex = HexString::new(s).unwrap();
    assert_eq!(hex.expose_secret(), "deadbeef");
    assert_eq!(hex.byte_len(), 4);
}
