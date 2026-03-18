#![cfg(feature = "no-alloc")]
// `no-alloc` feature: Fixed-only tests. Dynamic<T> is unavailable under this feature.
// IMPORTANT: This file must NEVER import secure_gate::Dynamic or use alloc::*
//            Dynamic requires the alloc feature → compile error under no-alloc
//            Only Fixed<[u8; N]> and primitive/stack types are allowed here.

use secure_gate::{ExposeSecret, ExposeSecretMut, Fixed};

// === Fixed<T> under no-alloc ===

#[test]
fn fixed_access_no_alloc() {
    let key = Fixed::new([1u8, 2, 3, 4]);
    key.with_secret(|s| assert_eq!(s, &[1, 2, 3, 4]));
}

#[test]
fn fixed_mutation_no_alloc() {
    let mut key = Fixed::new([0u8; 4]);
    key.with_secret_mut(|s| s[0] = 42);
    key.with_secret(|s| assert_eq!(s, &[42, 0, 0, 0]));
}

#[test]
fn fixed_zero_cost_no_alloc() {
    let key = Fixed::new([0u8; 32]);
    assert_eq!(core::mem::size_of_val(&key), 32);
}
