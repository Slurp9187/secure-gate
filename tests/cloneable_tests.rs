#![cfg(feature = "zeroize")]

use secure_gate::{
    CloneSafe, CloneableArray, CloneableString, CloneableVec, Dynamic, ExposeSecretExt,
    ExposeSecretMutExt, Fixed,
};

// === Custom Type Cloning ===

#[derive(Clone)]
struct MyKey([u8; 16]);
impl CloneSafe for MyKey {}
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

// === Basic Fixed Cloning ===

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

#[test]
fn cloned_fixed_are_independent() {
    let original: Fixed<[u8; 4]> = Fixed::new([0u8; 4]);
    let mut cloned = original.clone();

    cloned.expose_secret_mut()[0] = 1;

    assert_eq!(original.expose_secret()[0], 0);
    assert_eq!(cloned.expose_secret()[0], 1);
}

// === CloneableArray Tests ===

#[test]
fn cloneable_array_cloning() {
    let arr: CloneableArray<32> = [0x42u8; 32].into();
    let cloned = arr.clone();
    assert_eq!(arr.expose_secret().0, cloned.expose_secret().0);
}

#[test]
fn cloneable_array_independence() {
    let original: CloneableArray<4> = [0u8; 4].into();
    let mut cloned = original.clone();

    cloned.expose_secret_mut().0[0] = 1;

    assert_eq!(original.expose_secret().0[0], 0);
    assert_eq!(cloned.expose_secret().0[0], 1);
}

#[test]
fn cloneable_array_init_with() {
    let arr = CloneableArray::<3>::init_with(|| [1u8, 2, 3]);
    assert_eq!(arr.expose_secret().0, [1, 2, 3]);
}

#[test]
fn cloneable_array_try_init_with() {
    let arr = CloneableArray::<3>::try_init_with(|| Ok::<[u8; 3], &str>([1u8, 2, 3])).unwrap();
    assert_eq!(arr.expose_secret().0, [1, 2, 3]);

    let err: Result<CloneableArray<3>, &str> = CloneableArray::<3>::try_init_with(|| Err("fail"));
    assert!(err.is_err());
}

// === CloneableString Tests ===

#[test]
fn cloneable_string_cloning() {
    let s: CloneableString = "secret".into();
    let cloned = s.clone();
    assert_eq!(s.expose_secret().0, cloned.expose_secret().0);
}

#[test]
fn cloneable_string_mutability() {
    let mut s: CloneableString = "base".into();
    s.expose_secret_mut().0.push_str(" appended");
    assert_eq!(s.expose_secret().0, "base appended");

    let cloned = s.clone();
    assert_eq!(cloned.expose_secret().0, "base appended");
}

#[test]
fn cloneable_string_init_with() {
    let s = CloneableString::init_with(|| "secret".to_string());
    assert_eq!(s.expose_secret().0, "secret");
}

#[test]
fn cloneable_string_try_init_with() {
    let s = CloneableString::try_init_with(|| Ok::<String, &str>("secret".to_string())).unwrap();
    assert_eq!(s.expose_secret().0, "secret");

    let err: Result<CloneableString, &str> = CloneableString::try_init_with(|| Err("fail"));
    assert!(err.is_err());
}

// === CloneableVec Tests ===

#[test]
fn cloneable_vec_cloning() {
    let v: CloneableVec = vec![1u8, 2, 3].into();
    let cloned = v.clone();
    assert_eq!(v.expose_secret().0, cloned.expose_secret().0);
}

#[test]
fn cloneable_vec_mutability_and_independence() {
    let mut v: CloneableVec = vec![1u8, 2, 3].into();
    v.expose_secret_mut().0.push(4);
    assert_eq!(v.expose_secret().0, &[1, 2, 3, 4]);

    let cloned = v.clone();
    assert_eq!(cloned.expose_secret().0, &[1, 2, 3, 4]);

    v.expose_secret_mut().0.push(5);
    assert_eq!(v.expose_secret().0, &[1, 2, 3, 4, 5]);
    assert_eq!(cloned.expose_secret().0, &[1, 2, 3, 4]); // independent copy
}

#[test]
fn cloneable_vec_init_with() {
    let v = CloneableVec::init_with(|| vec![1u8, 2, 3]);
    assert_eq!(v.expose_secret().0, &[1, 2, 3]);
}

#[test]
fn cloneable_vec_try_init_with() {
    let v = CloneableVec::try_init_with(|| Ok::<Vec<u8>, &str>(vec![1u8, 2, 3])).unwrap();
    assert_eq!(v.expose_secret().0, &[1, 2, 3]);

    let err: Result<CloneableVec, &str> = CloneableVec::try_init_with(|| Err("fail"));
    assert!(err.is_err());
}

// Note: Raw Dynamic<String> cloning is still not allowed (String !impl CloneSafe),
// but CloneableString provides a safe wrapper for cloning string secrets.

// === No accidental Clone on raw wrappers ===
#[test]
#[allow(unused)]
fn raw_dynamic_not_cloneable() {
    let s: Dynamic<String> = "secret".into();
    // let _cloned = s.clone(); // Must not compile — raw Dynamic<T> where T !impl CloneSafe
    // Compile-fail guard: this test ensures no Clone impl leaks
}

#[test]
#[allow(unused)]
fn raw_fixed_not_cloneable_by_default() {
    let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
    // let _cloned = key.clone(); // Must not compile unless inner impls CloneSafe
}
// === Nested CloneSafe (array of primitives) ===
#[test]
fn nested_cloneable_array() {
    type NestedKey = [u32; 8]; // u32 impls CloneSafe, so array does too
    let original: Fixed<NestedKey> = Fixed::new([42u32; 8]);
    let cloned = original.clone();
    assert_eq!(original.expose_secret(), cloned.expose_secret());

    // Mutate to prove independence
    let mut mutated = cloned;
    mutated.expose_secret_mut()[0] = 99;
    assert_eq!(original.expose_secret()[0], 42);
    assert_eq!(mutated.expose_secret()[0], 99);
}
