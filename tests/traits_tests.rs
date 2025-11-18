// tests/traits_tests.rs (actual file name)
//
// Test trait extensions for ergonomic secret access

use std::string::String;
use std::vec::Vec;

use secure_gate::heap::HeapSecure;
#[cfg(feature = "zeroize")]
use secure_gate::{ExposeSecret, ExposeSecretMut, SecurePassword, SecurePasswordBuilder};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;
#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "zeroize")]
#[test]
fn test_direct_expose_secret_on_secure_password() {
    let pw: SecurePassword = "test".into();
    assert_eq!(pw.expose_secret(), "test"); // ← &str, works!
}

#[cfg(feature = "zeroize")]
#[test]
fn test_direct_expose_secret_mut_on_secure_password_builder() {
    let mut builder: SecurePasswordBuilder = "test".into();
    builder.expose_secret_mut().push_str("mutated");
    assert_eq!(builder.expose_secret(), "testmutated");
}

#[cfg(feature = "zeroize")]
#[test]
fn test_finish_mut_shrink_string() {
    let mut s: HeapSecure<String> = HeapSecure::new(String::with_capacity(100));
    s.expose_mut().push_str("short");
    let old_cap = s.expose().capacity();
    s.finish_mut();
    let new_cap = s.expose().capacity();
    assert!(new_cap <= old_cap, "capacity should not increase");
    assert!(new_cap >= s.expose().len(), "capacity should fit content");
    assert_eq!(s.expose(), "short");
}

#[cfg(feature = "zeroize")]
#[test]
fn test_finish_mut_shrink_vec() {
    let mut v: HeapSecure<Vec<u8>> = HeapSecure::new(Vec::with_capacity(100));
    v.expose_mut().extend_from_slice(b"short");
    let old_cap = v.expose().capacity();
    v.finish_mut();
    let new_cap = v.expose().capacity();
    assert!(new_cap <= old_cap, "capacity should not increase");
    assert!(new_cap >= v.expose().len(), "capacity should fit content");
    assert_eq!(v.expose().as_slice(), b"short");
}

#[cfg(not(feature = "zeroize"))]
#[test]
fn test_finish_mut_fallback_string() {
    let mut s: HeapSecure<String> = HeapSecure::new(String::with_capacity(100));
    s.expose_mut().push_str("short");
    let old_cap = s.expose().capacity();
    s.finish_mut();
    let new_cap = s.expose().capacity();
    assert!(new_cap <= old_cap, "capacity should not increase");
    assert!(new_cap >= s.expose().len(), "capacity should fit content");
    assert_eq!(s.expose(), "short");
}

#[cfg(not(feature = "zeroize"))]
#[test]
fn test_finish_mut_fallback_vec() {
    let mut v: HeapSecure<Vec<u8>> = HeapSecure::new(Vec::with_capacity(100));
    v.expose_mut().extend_from_slice(b"short");
    let old_cap = v.expose().capacity();
    v.finish_mut();
    let new_cap = v.expose().capacity();
    assert!(new_cap <= old_cap, "capacity should not increase");
    assert!(new_cap >= v.expose().len(), "capacity should fit content");
    assert_eq!(v.expose().as_slice(), b"short");
}

#[cfg(feature = "zeroize")]
#[test]
fn test_zeroize_on_drop_trait_application() {
    #[derive(Zeroize, ZeroizeOnDrop)]
    struct TestSecret {
        data: Vec<u8>,
    }

    let secret = HeapSecure::new(TestSecret {
        data: vec![1, 2, 3],
    });
    assert_eq!(secret.expose().data, vec![1, 2, 3]);
    drop(secret);
    // Test passes if no panic (ZeroizeOnDrop invoked correctly)
}
