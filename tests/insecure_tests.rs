#![cfg(feature = "insecure")]

// Tests for insecure mode: wrappers as conduits without zeroize/ct-eq dependencies.
// Ensures stripped functionality works for embedded/lightweight use cases.

use secure_gate::*;

// === Core Functionality in Insecure Mode ===

#[test]
fn insecure_dynamic_access() {
    let secret: Dynamic<String> = "insecure_secret".to_string().into();
    assert_eq!(secret.expose_secret().as_str(), "insecure_secret");
}

#[test]
fn insecure_fixed_access() {
    let secret: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    assert_eq!(secret.expose_secret(), &[1, 2, 3, 4]);
}

#[test]
fn insecure_dynamic_mutability() {
    let mut secret: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    secret.expose_secret_mut().push(4);
    assert_eq!(secret.expose_secret().as_slice(), &[1, 2, 3, 4]);
}

#[test]
fn insecure_fixed_mutability() {
    let mut secret: Fixed<[u8; 4]> = Fixed::new([0; 4]);
    secret.expose_secret_mut()[0] = 42;
    assert_eq!(secret.expose_secret(), &[42, 0, 0, 0]);
}

// === Cloning in Insecure + Cloneable Mode ===

#[cfg(feature = "cloneable")]
mod insecure_cloneable {
    use super::*;

    cloneable_dynamic_alias!(InsecureString, String);
    cloneable_fixed_alias!(InsecureKey, 4);
    cloneable_dynamic_alias!(InsecureVec, Vec<u8>);

    #[test]
    fn insecure_cloneable_dynamic() {
        let original: InsecureString = "clone_me".to_string().into();
        let cloned = original.clone();
        assert_eq!(
            original.expose_secret().as_str(),
            cloned.expose_secret().as_str()
        );
    }

    #[test]
    fn insecure_cloneable_fixed() {
        let original: InsecureKey = [1, 2, 3, 4].into();
        let cloned = original.clone();
        assert_eq!(original.expose_secret(), cloned.expose_secret());
    }

    #[test]
    fn insecure_cloneable_vec() {
        let original: InsecureVec = vec![5, 6, 7].into();
        let cloned = original.clone();
        assert_eq!(
            original.expose_secret().as_slice(),
            cloned.expose_secret().as_slice()
        );
    }

    #[test]
    fn insecure_cloneable_independence() {
        let mut original: InsecureVec = vec![1].into();
        let cloned = original.clone();
        original.expose_secret_mut().push(2);
        assert_eq!(original.expose_secret().as_slice(), &[1, 2]);
        assert_eq!(cloned.expose_secret().as_slice(), &[1]); // independent
    }
}

// === No Security Features (ct-eq unavailable) ===

// Note: In insecure mode, ct_eq is not available, so we can't test it.
// If code tries to use ct_eq, it would fail to compile.

// === Macro and Trait Availability ===

#[test]
fn insecure_trait_access() {
    // ExposeSecret etc. should still work
    let secret: Dynamic<String> = "test".into();
    assert!(secret.len() > 0);
    assert!(!secret.is_empty());
}
