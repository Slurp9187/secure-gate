#![cfg(feature = "ct-eq")]

extern crate alloc;

use secure_gate::{
    cloneable_dynamic_alias, cloneable_fixed_alias, exportable_dynamic_alias,
    exportable_fixed_alias, ConstantTimeEq, ExposeSecret,
};

// Define test types using macros
cloneable_fixed_alias!(pub TestCloneableArray, 4);
cloneable_dynamic_alias!(pub TestCloneableString, String);
cloneable_dynamic_alias!(pub TestCloneableVec, Vec<u8>);
exportable_fixed_alias!(pub TestExportableArray, 4);
exportable_dynamic_alias!(pub TestExportableString, String);
exportable_dynamic_alias!(pub TestExportableVec, Vec<u8>);

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

#[test]
fn test_cloneable_array_ct_eq() {
    let a: TestCloneableArray = [1u8, 2, 3, 4].into();
    let b: TestCloneableArray = [1u8, 2, 3, 4].into();
    let c: TestCloneableArray = [1u8, 2, 3, 5].into();

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}

#[test]
fn test_cloneable_string_ct_eq() {
    let a: TestCloneableString = "test".to_string().into();
    let b: TestCloneableString = "test".to_string().into();
    let c: TestCloneableString = "fail".to_string().into();

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}

#[test]
fn test_cloneable_vec_ct_eq() {
    let a: TestCloneableVec = vec![1, 2, 3].into();
    let b: TestCloneableVec = vec![1, 2, 3].into();
    let c: TestCloneableVec = vec![1, 2, 4].into();

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}

#[test]
fn test_exportable_array_ct_eq() {
    let a: TestExportableArray = [1u8, 2, 3, 4].into();
    let b: TestExportableArray = [1u8, 2, 3, 4].into();
    let c: TestExportableArray = [1u8, 2, 3, 5].into();

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}

#[test]
fn test_exportable_string_ct_eq() {
    let a: TestExportableString = "test".to_string().into();
    let b: TestExportableString = "test".to_string().into();
    let c: TestExportableString = "fail".to_string().into();

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}

#[test]
fn test_exportable_vec_ct_eq() {
    let a: TestExportableVec = vec![1, 2, 3].into();
    let b: TestExportableVec = vec![1, 2, 3].into();
    let c: TestExportableVec = vec![1, 2, 4].into();

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}
