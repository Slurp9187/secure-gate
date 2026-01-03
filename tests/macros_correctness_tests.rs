// ==========================================================================
// tests/macros_correctness_tests.rs
// ==========================================================================
// Exhaustive tests for macro correctness and safety

#![cfg(test)]

use secure_gate::{dynamic_alias, fixed_alias};

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
