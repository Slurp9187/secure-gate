#![cfg(feature = "ct-eq")]

extern crate alloc;

use secure_gate::ConstantTimeEq;

#[test]
fn test_slice_ct_eq() {
    let a = [1u8, 2, 3].as_slice();
    let b = [1u8, 2, 3].as_slice();
    let c = [1u8, 2, 4].as_slice();

    assert!(a.ct_eq(b));
    assert!(!a.ct_eq(c));
}

#[test]
fn test_array_ct_eq() {
    let a: [u8; 4] = [1, 2, 3, 4];
    let b: [u8; 4] = [1, 2, 3, 4];
    let c: [u8; 4] = [1, 2, 3, 5];

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}

#[test]
fn test_vec_ct_eq() {
    let a: Vec<u8> = vec![1, 2, 3];
    let b: Vec<u8> = vec![1, 2, 3];
    let c: Vec<u8> = vec![1, 2, 4];

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}

#[test]
fn test_string_ct_eq() {
    let a: String = "hello".to_string();
    let b: String = "hello".to_string();
    let c: String = "world".to_string();

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}
