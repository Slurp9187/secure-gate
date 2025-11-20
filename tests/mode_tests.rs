// tests/temp_tests.rs
//
// Safe, exhaustive validation of ZeroizeMode and unsafe-wipe behavior

#![cfg(feature = "zeroize")]

use secure_gate::{secure_gate::ZeroizeMode, SecureGate};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn safe_mode_only_wipes_used_bytes_string() {
    let mut s = SecureGate::new("hello".to_string());
    s.expose_mut().push_str(" world");
    let used_len = s.expose().len();

    s.zeroize();

    assert_eq!(s.expose().as_str(), "\0".repeat(used_len));
}

#[test]
#[cfg(feature = "unsafe-wipe")]
fn full_mode_wipes_visible_bytes() {
    let mut s = SecureGate::new_full_wipe("data".to_string());
    s.zeroize();
    assert_eq!(s.expose().as_str(), "\0\0\0\0");
}

#[test]
fn passthrough_mode_leaves_data_intact() {
    let mut s = SecureGate::new_passthrough("sensitive".to_string());
    s.zeroize();
    assert_eq!(s.expose().as_str(), "sensitive");
}

#[test]
#[cfg(feature = "unsafe-wipe")]
fn with_mode_controls_behavior() {
    let mut safe = SecureGate::with_mode("abcd".to_string(), ZeroizeMode::Safe);
    let mut full = SecureGate::with_mode("abcd".to_string(), ZeroizeMode::Full);
    let mut pass = SecureGate::with_mode("abcd".to_string(), ZeroizeMode::Passthrough);

    safe.zeroize();
    full.zeroize();
    pass.zeroize();

    assert_eq!(safe.expose().as_str(), "\0\0\0\0");
    assert_eq!(full.expose().as_str(), "\0\0\0\0");
    assert_eq!(pass.expose().as_str(), "abcd");
}

#[test]
#[cfg(feature = "unsafe-wipe")]
fn vec_u8_full_mode_wipes_visible_bytes() {
    let mut v = SecureGate::new_full_wipe(vec![9; 100]);
    v.zeroize();
    assert!(v.expose().iter().all(|&b| b == 0));
}

#[test]
fn vec_u8_safe_mode_wipes_visible_bytes() {
    let mut v = SecureGate::new(vec![9; 100]);
    v.zeroize();
    assert!(v.expose().iter().all(|&b| b == 0));
}

#[test]
fn unsized_types_work() {
    let r#unsized: SecureGate<str> = SecureGate::new_unsized("hello".into());
    assert_eq!(r#unsized.expose(), "hello");
}

#[test]
fn zeroize_on_drop_calls_inner_zeroize() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[derive(Zeroize, ZeroizeOnDrop)]
    struct Tracked(u32);

    impl Tracked {
        fn new() -> Self {
            COUNTER.fetch_add(1, Ordering::Relaxed);
            Tracked(0xDEADBEEF)
        }
    }

    drop(SecureGate::new_full_wipe(Tracked::new()));
    assert_eq!(COUNTER.load(Ordering::Relaxed), 1);
}

#[test]
#[cfg(feature = "unsafe-wipe")]
fn empty_but_allocated_vec_is_handled() {
    let mut v = SecureGate::new_full_wipe(Vec::<u8>::with_capacity(1000));
    v.expose_mut().clear();
    v.zeroize(); // no panic = success
}

#[test]
fn default_constructor_is_safe_mode() {
    let mut s = SecureGate::new("test".to_string());
    s.zeroize();
    assert_eq!(s.expose().as_str(), "\0\0\0\0");
}

#[test]
fn capacity_never_shrinks_on_zeroize() {
    let mut v = SecureGate::new(vec![0u8; 10]);
    v.expose_mut().reserve(1000);
    let old_cap = v.expose().capacity();
    v.zeroize();
    assert!(v.expose().capacity() >= old_cap, "capacity must not shrink");
}

#[test]
#[cfg(feature = "unsafe-wipe")]
fn clone_preserves_full_wipe_mode() {
    let s1 = SecureGate::new_full_wipe("secret".to_string());
    let mut s2 = s1.clone();
    s2.zeroize();
    assert_eq!(s2.expose().as_str(), "\0\0\0\0\0\0");
}

#[test]
fn clone_preserves_safe_mode() {
    let s1 = SecureGate::new("secret".to_string());
    let mut s2 = s1.clone();
    s2.zeroize();
    assert_eq!(s2.expose().as_str(), "\0\0\0\0\0\0");
}

#[test]
fn init_with_uses_safe_mode() {
    let mut s = SecureGate::init_with(|| "built".to_string());
    s.zeroize();
    assert_eq!(s.expose().as_str(), "\0\0\0\0\0");
}
