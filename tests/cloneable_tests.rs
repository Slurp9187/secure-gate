#![cfg(feature = "zeroize")]

use secure_gate::{CloneableArray, CloneableSecretMarker, CloneableString, CloneableVec, Fixed};

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
impl CloneableSecretMarker for MyKey {}
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

#[test]
fn cloneable_array_cloning() {
    let arr: CloneableArray<32> = [0x42u8; 32].into();
    let cloned = arr.clone();
    assert_eq!(arr.expose_inner(), cloned.expose_inner());
}

#[test]
fn cloneable_array_independence() {
    let original: CloneableArray<4> = [0u8; 4].into();
    let mut cloned = original.clone();

    cloned.expose_inner_mut()[0] = 1;

    assert_eq!(original.expose_inner()[0], 0);
    assert_eq!(cloned.expose_inner()[0], 1);
}

#[test]
fn cloneable_string_cloning() {
    let s: CloneableString = "secret".into();
    let cloned = s.clone();
    assert_eq!(s.expose_inner(), cloned.expose_inner());
}

#[test]
fn cloneable_string_mutability() {
    let mut s: CloneableString = "base".into();
    s.expose_inner_mut().push_str(" appended");
    assert_eq!(s.expose_inner(), "base appended");

    let cloned = s.clone();
    assert_eq!(cloned.expose_inner(), "base appended");
}

#[test]
fn cloneable_vec_cloning() {
    let v: CloneableVec = vec![1u8, 2, 3].into();
    let cloned = v.clone();
    assert_eq!(v.expose_inner(), cloned.expose_inner());
}

#[test]
fn cloneable_vec_mutability_and_independence() {
    let mut v: CloneableVec = vec![1u8, 2, 3].into();
    v.expose_inner_mut().push(4);
    assert_eq!(v.expose_inner(), &[1, 2, 3, 4]);

    let cloned = v.clone();
    assert_eq!(cloned.expose_inner(), &[1, 2, 3, 4]);

    v.expose_inner_mut().push(5);
    assert_eq!(v.expose_inner(), &[1, 2, 3, 4, 5]);
    assert_eq!(cloned.expose_inner(), &[1, 2, 3, 4]); // independent
}

#[test]
fn cloneable_string_init_with() {
    let s = CloneableString::init_with(|| "secret".to_string());
    assert_eq!(s.expose_inner(), "secret");
}

#[test]
fn cloneable_string_try_init_with() {
    let s = CloneableString::try_init_with(|| Ok::<String, &str>("secret".to_string())).unwrap();
    assert_eq!(s.expose_inner(), "secret");

    let err: Result<CloneableString, &str> = CloneableString::try_init_with(|| Err("fail"));
    assert!(err.is_err());
}

#[test]
fn cloneable_vec_init_with() {
    let v = CloneableVec::init_with(|| vec![1u8, 2, 3]);
    assert_eq!(v.expose_inner(), &[1, 2, 3]);
}

#[test]
fn cloneable_vec_try_init_with() {
    let v = CloneableVec::try_init_with(|| Ok::<Vec<u8>, &str>(vec![1u8, 2, 3])).unwrap();
    assert_eq!(v.expose_inner(), &[1, 2, 3]);

    let err: Result<CloneableVec, &str> = CloneableVec::try_init_with(|| Err("fail"));
    assert!(err.is_err());
}

// Note: Raw Dynamic<String> cloning is still not allowed (String !impl CloneableSecretMarker),
// but CloneableString provides a safe wrapper for cloning string secrets.
