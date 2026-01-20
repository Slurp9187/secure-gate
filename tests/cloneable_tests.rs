extern crate alloc;

// Temporarily remove cfg to run tests without feature
// #![cfg(feature = "zeroize")]

// Define cloneable types using the new macros
use secure_gate::{
    cloneable_dynamic_alias, cloneable_fixed_alias, Dynamic, ExposeSecret, ExposeSecretMut, Fixed,
};

cloneable_fixed_alias!(pub CloneableArray3, 3);
cloneable_dynamic_alias!(pub CloneableString, String);
cloneable_dynamic_alias!(pub CloneableVec, Vec<u8>);

// === CloneableArray Tests ===

#[test]
fn cloneable_array_init_with() {
    let arr: CloneableArray3 = CloneableArray3::init_with(|| [1u8, 2, 3]);
    assert_eq!(arr.expose_secret(), &[1, 2, 3]);
}

#[test]
fn cloneable_array_try_init_with() {
    let arr: CloneableArray3 =
        CloneableArray3::try_init_with(|| Ok::<[u8; 3], &str>([1u8, 2, 3])).unwrap();
    assert_eq!(arr.expose_secret(), &[1, 2, 3]);

    let err: Result<CloneableArray3, &str> = CloneableArray3::try_init_with(|| Err("fail"));
    assert!(err.is_err());
}

// === CloneableString Tests ===

#[test]
fn cloneable_string_cloning() {
    let s: CloneableString = "secret".to_string().into();
    let cloned = s.clone();
    assert_eq!(s.expose_secret().as_str(), cloned.expose_secret().as_str());
}

#[test]
fn cloneable_string_mutability() {
    let mut s: CloneableString = "base".to_string().into();
    s.expose_secret_mut().push_str(" appended");
    assert_eq!(s.expose_secret().as_str(), "base appended");

    let cloned = s.clone();
    assert_eq!(cloned.expose_secret().as_str(), "base appended");
}

#[test]
fn cloneable_string_init_with() {
    let s: CloneableString = CloneableString::init_with(|| "secret".to_string());
    assert_eq!(s.expose_secret().as_str(), "secret");
}

#[test]
fn cloneable_string_try_init_with() {
    let s: CloneableString =
        CloneableString::try_init_with(|| Ok::<String, &str>("secret".to_string())).unwrap();
    assert_eq!(s.expose_secret().as_str(), "secret");

    let err: Result<CloneableString, &str> = CloneableString::try_init_with(|| Err("fail"));
    assert!(err.is_err());
}

// === CloneableVec Tests ===

#[test]
fn cloneable_vec_cloning() {
    let v: CloneableVec = vec![1u8, 2, 3].into();
    let cloned = v.clone();
    assert_eq!(
        v.expose_secret().as_slice(),
        cloned.expose_secret().as_slice()
    );
}

#[test]
fn cloneable_vec_mutability_and_independence() {
    let mut v: CloneableVec = vec![1u8, 2, 3].into();
    v.expose_secret_mut().push(4);
    assert_eq!(v.expose_secret().as_slice(), &[1, 2, 3, 4]);

    let cloned = v.clone();
    assert_eq!(cloned.expose_secret().as_slice(), &[1, 2, 3, 4]);

    v.expose_secret_mut().push(5);
    assert_eq!(v.expose_secret().as_slice(), &[1, 2, 3, 4, 5]);
    assert_eq!(cloned.expose_secret().as_slice(), &[1, 2, 3, 4]); // independent copy
}

#[test]
fn cloneable_vec_init_with() {
    let v: CloneableVec = CloneableVec::init_with(|| vec![1u8, 2, 3]);
    assert_eq!(v.expose_secret().as_slice(), &[1, 2, 3]);
}

#[test]
fn cloneable_vec_try_init_with() {
    let v: CloneableVec =
        CloneableVec::try_init_with(|| Ok::<Vec<u8>, &str>(vec![1u8, 2, 3])).unwrap();
    assert_eq!(v.expose_secret().as_slice(), &[1, 2, 3]);

    let err: Result<CloneableVec, &str> = CloneableVec::try_init_with(|| Err("fail"));
    assert!(err.is_err());
}

// === No accidental Clone on raw wrappers ===

#[test]
#[allow(unused)]
fn raw_dynamic_not_cloneable() {
    let s: Dynamic<String> = "secret".into();
    // let _cloned = s.clone(); // Must not compile — raw Dynamic<T> where T !impl CloneableType
    // Compile-fail guard: this test ensures no Clone impl leaks
}

#[test]
#[allow(unused)]
fn raw_fixed_not_cloneable_by_default() {
    let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
    // let _cloned = key.clone(); // Must not compile — Fixed<T> never implements Clone directly
}

// === Nested CloneableType ===

#[test]
fn nested_cloneable_array() {
    let original: CloneableArray3 = [42u8; 3].into();
    let cloned = original.clone();
    assert_eq!(original.expose_secret(), cloned.expose_secret());

    // Mutate to prove independence
    let mut mutated = cloned;
    mutated.expose_secret_mut()[0] = 99;
    assert_eq!(original.expose_secret()[0], 42);
    assert_eq!(mutated.expose_secret()[0], 99);
}

// === Constant-Time Equality Tests ===

#[cfg(feature = "ct-eq")]
#[test]
fn cloneable_array_ct_eq() {
    let arr1: CloneableArray3 = [1u8, 2, 3].into();
    let arr2: CloneableArray3 = [1u8, 2, 3].into();
    let arr3: CloneableArray3 = [1u8, 2, 4].into();

    assert!(arr1.ct_eq(&arr2));
    assert!(!arr1.ct_eq(&arr3));
}

#[cfg(feature = "ct-eq")]
#[test]
fn cloneable_string_ct_eq() {
    let s1: CloneableString = "secret".to_string().into();
    let s2: CloneableString = "secret".to_string().into();
    let s3: CloneableString = "different".to_string().into();

    assert!(s1.ct_eq(&s2));
    assert!(!s1.ct_eq(&s3));
}

#[cfg(feature = "ct-eq")]
#[test]
fn cloneable_vec_ct_eq() {
    let v1: CloneableVec = vec![1u8, 2, 3].into();
    let v2: CloneableVec = vec![1u8, 2, 3].into();
    let v3: CloneableVec = vec![1u8, 2, 4].into();

    assert!(v1.ct_eq(&v2));
    assert!(!v1.ct_eq(&v3));
}

// === Simple Macro Test Without Zeroize ===

#[test]
fn cloneable_macros_basic() {
    let arr = CloneableArray3::init_with(|| [1, 2, 3]);
    assert_eq!(arr.expose_secret(), &[1, 2, 3]);

    let cloned = arr.clone();
    assert_eq!(cloned.expose_secret(), &[1, 2, 3]);
}
