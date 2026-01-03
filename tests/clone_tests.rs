#![cfg(feature = "zeroize")]

use secure_gate::{CloneableSecret, Fixed};

#[test]
fn fixed_arrays_can_be_cloned() {
    let key1: Fixed<[u8; 32]> = Fixed::new([0x42u8; 32]);
    let key2 = key1.clone();
    assert_eq!(key1.expose_secret(), key2.expose_secret());
}

#[test]
fn primitives_can_be_cloned() {
    let fixed_u32: Fixed<u32> = Fixed::new(12345);
    let cloned = fixed_u32.clone();
    assert_eq!(*fixed_u32.expose_secret(), *cloned.expose_secret());
}

#[derive(Clone)]
struct MyKey([u8; 16]);
impl CloneableSecret for MyKey {}
impl zeroize::Zeroize for MyKey {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

#[test]
fn custom_type_cloneable_secret_enables_cloning() {
    let key: Fixed<MyKey> = Fixed::new(MyKey([1u8; 16]));
    let cloned = key.clone();
    assert_eq!(key.expose_secret().0, cloned.expose_secret().0);
}

#[test]
fn cloned_fixed_are_independent() {
    let original: Fixed<[u8; 4]> = Fixed::new([0u8; 4]);
    let mut cloned = original.clone();

    cloned.expose_secret_mut()[0] = 1;

    assert_eq!(original.expose_secret()[0], 0);
    assert_eq!(cloned.expose_secret()[0], 1);
}

// Note: Dynamic<String> cloning is not allowed by default (String !impl CloneableSecret)
// so no test for that—its a compile error.
