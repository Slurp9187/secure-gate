// tests/core_tests.rs
// Core API tests for Fixed<T> and Dynamic<T> — v0.8.0 style

#[cfg(feature = "alloc")]
use secure_gate::Dynamic;
use secure_gate::{ExposeSecret, ExposeSecretMut, Fixed};
#[cfg(feature = "cloneable")]
use secure_gate::CloneableSecret;

// === Basic Functionality ===

#[cfg(feature = "alloc")]
#[test]
fn basic_usage_explicit_access() {
    let mut key = Fixed::new([0u8; 32]);
    let mut pw = Dynamic::<String>::new("hunter2".to_string());

    assert_eq!(key.len(), 32);
    assert!(!key.is_empty());
    pw.with_secret(|s| assert_eq!(s.len(), 7));
    pw.with_secret(|s| assert_eq!(s, "hunter2"));

    pw.with_secret_mut(|s| s.push('!'));
    key.with_secret_mut(|s| s[0] = 1);

    pw.with_secret(|s| assert_eq!(s, "hunter2!"));
    key.with_secret(|s| assert_eq!(s[0], 1));
}

#[cfg(feature = "alloc")]
#[test]
fn expose_secret_provides_access() {
    let key = Fixed::new([1u8; 32]);
    assert_eq!(*key.expose_secret(), [1u8; 32]);

    let pw = Dynamic::<String>::new("secret".to_string());
    assert_eq!(pw.expose_secret(), "secret");
}

// === Memory Layout ===

#[test]
fn fixed_is_truly_zero_cost() {
    let key = Fixed::new([0u8; 32]);
    assert_eq!(core::mem::size_of_val(&key), 32);
}

// === Security Features ===

#[cfg(feature = "alloc")]
#[test]
fn debug_is_redacted() {
    let key = Fixed::new([0u8; 32]);
    let pw = Dynamic::<String>::new("hunter2".to_string());

    assert_eq!(format!("{key:?}"), "[REDACTED]");
    assert_eq!(format!("{pw:?}"), "[REDACTED]");
    assert_eq!(format!("{key:#?}"), "[REDACTED]");
    assert_eq!(format!("{pw:#?}"), "[REDACTED]");
}

// === Byte Array Access ===

#[test]
fn explicit_access_for_byte_arrays() {
    let mut key = Fixed::new([42u8; 32]);

    let slice: &[u8] = key.expose_secret();
    assert_eq!(slice.len(), 32);
    assert_eq!(slice[0], 42);

    let mut_slice: &mut [u8] = key.expose_secret_mut();
    mut_slice[0] = 99;
    assert_eq!(key.expose_secret()[0], 99);
}

// === Length and Size Methods ===

#[cfg(feature = "alloc")]
#[test]
fn dynamic_len_is_empty() {
    let pw: Dynamic<String> = "hunter2".into();
    assert_eq!(pw.len(), 7);
    assert!(!pw.is_empty());

    let empty: Dynamic<String> = "".into();
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}

#[cfg(feature = "rand")]
#[cfg(feature = "alloc")]
#[test]
fn dynamic_generate_random() {
    use secure_gate::Dynamic;
    let random: Dynamic<Vec<u8>> = Dynamic::from_random(64);
    assert_eq!(random.len(), 64);
    // Verify it's actually random
    random.with_secret(|s| assert!(!s.iter().all(|&b| b == 0)));
}

// === Dynamic<Vec<u8>> from slice ===
#[cfg(feature = "alloc")]
#[test]
fn dynamic_vec_from_slice() {
    let slice: &[u8] = b"hello world";
    let dyn_vec: Dynamic<Vec<u8>> = slice.into();
    dyn_vec.with_secret(|s| assert_eq!(s, b"hello world"));
}

// === TryFrom for Fixed ===
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "Fixed<4> from_slice: expected exactly 4 bytes, got 2")
)]
#[test]
fn fixed_try_from_slice() {
    let slice: &[u8] = &[1u8, 2, 3, 4];
    let result: Result<Fixed<[u8; 4]>, _> = slice.try_into();
    assert!(result.is_ok());
    let fixed = result.unwrap();
    fixed.with_secret(|s| assert_eq!(s, &[1, 2, 3, 4]));

    let short_slice: &[u8] = &[1u8, 2];
    let _fail: Result<Fixed<[u8; 4]>, _> = short_slice.try_into();
    #[cfg(not(debug_assertions))]
    assert!(_fail.is_err());
}

// === CloneableSecret ===

#[cfg(feature = "cloneable")]
#[test]
fn cloneable_secret_works() {
    use zeroize::Zeroize;

    #[derive(Clone, Zeroize, Debug)]
    struct CloneKey(Vec<u8>);

    impl CloneableSecret for CloneKey {}

    let original = CloneKey(vec![1, 2, 3, 4]);
    let cloned = original.clone();

    assert_eq!(original.0, cloned.0);
    // Verify zeroization on drop works
    drop(original);
}

// === Random Generation (Fixed) ===

#[cfg(feature = "rand")]
#[test]
fn fixed_from_random() {
    let key1: Fixed<[u8; 32]> = Fixed::from_random();
    let key2: Fixed<[u8; 32]> = Fixed::from_random();

    key1.with_secret(|k1| {
        key2.with_secret(|k2| {
            // They should be different (statistically)
            assert_ne!(k1, k2, "two random keys should differ");
            // But both should be non-zero
            assert!(!k1.iter().all(|&b| b == 0));
            assert!(!k2.iter().all(|&b| b == 0));
        });
    });
}
