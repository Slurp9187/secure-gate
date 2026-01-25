#![cfg(feature = "insecure")]

extern crate alloc;

// Tests for insecure mode: wrappers as conduits without zeroize/ct-eq dependencies.
// Ensures stripped functionality works for embedded/lightweight use cases.

use secure_gate::*;

// === Core Functionality in Insecure Mode ===

#[test]
fn insecure_dynamic_access() {
    let secret: Dynamic<String> = "insecure_secret".to_string().into();
    secret.with_secret(|s| assert_eq!(s.as_str(), "insecure_secret"));
}

#[test]
fn insecure_fixed_access() {
    let secret: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    secret.with_secret(|s| assert_eq!(s, &[1, 2, 3, 4]));
}

#[test]
fn insecure_dynamic_mutability() {
    let mut secret: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    secret.with_secret_mut(|s| s.push(4));
    secret.with_secret(|s| assert_eq!(s.as_slice(), &[1, 2, 3, 4]));
}

#[test]
fn insecure_fixed_mutability() {
    let mut secret: Fixed<[u8; 4]> = Fixed::new([0; 4]);
    secret.with_secret_mut(|s| s[0] = 42);
    secret.with_secret(|s| assert_eq!(s, &[42, 0, 0, 0]));
}

// === Cloning in Insecure + Cloneable Mode ===

// === No Security Features (ct-eq unavailable) ===

// Note: In insecure mode, ct_eq is not available, so we can't test it.
// If code tries to use ct_eq, it would fail to compile.

// === Macro and Trait Availability ===

#[test]
fn insecure_trait_access() {
    // ExposeSecret etc. should still work
    let secret: Dynamic<String> = "test".into();
    assert!(ExposeSecret::len(&secret) > 0);
    assert!(!secret.is_empty());
}
