// ==========================================================================
// tests/core_tests.rs
// ==========================================================================
// Core integration tests — pure v0.6.0 API

use secure_gate::{Dynamic, ExposeSecretExt, ExposeSecretMutExt, Fixed, SecureMetadataExt};

// === Basic Functionality ===

#[test]
fn basic_usage_explicit_access() {
    let mut key = Fixed::new([0u8; 32]);
    let mut pw = Dynamic::<String>::new("hunter2".to_string());

    assert_eq!(key.len(), 32);
    assert!(!key.is_empty());
    assert_eq!(pw.expose_secret().len(), 7);
    assert_eq!(pw.expose_secret(), "hunter2");

    pw.expose_secret_mut().push('!');
    key.expose_secret_mut()[0] = 1;

    assert_eq!(pw.expose_secret(), "hunter2!");
    assert_eq!(key.expose_secret()[0], 1);
}

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
#[test]
fn rng_len_is_empty() {
    use secure_gate::{DynamicRandom, FixedRandom};

    let rng: FixedRandom<32> = FixedRandom::generate();
    assert_eq!(rng.len(), 32);
    assert!(!rng.is_empty());

    let dyn_rng: DynamicRandom = DynamicRandom::generate(64);
    assert_eq!(dyn_rng.len(), 64);
    assert!(!dyn_rng.is_empty());

    let empty: DynamicRandom = DynamicRandom::generate(0);
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}

// === Random Generation ===

#[cfg(feature = "rand")]
#[test]
fn fixed_generate_random() {
    use secure_gate::Fixed;
    let key: Fixed<[u8; 32]> = Fixed::generate_random();
    assert_eq!(key.len(), 32);
    // Verify it's actually random (not all zeros)
    assert!(!key.expose_secret().iter().all(|&b| b == 0));
}

#[cfg(feature = "rand")]
#[test]
fn dynamic_generate_random() {
    use secure_gate::Dynamic;
    let random: Dynamic<Vec<u8>> = Dynamic::generate_random(64);
    assert_eq!(random.len(), 64);
    // Verify it's actually random
    assert!(!random.expose_secret().iter().all(|&b| b == 0));
}

// === Dynamic<Vec<u8>> from slice ===
#[test]
fn dynamic_vec_from_slice() {
    let slice: &[u8] = b"hello world";
    let dyn_vec: Dynamic<Vec<u8>> = slice.into();
    assert_eq!(dyn_vec.expose_secret(), b"hello world");
    assert_eq!(dyn_vec.len(), 11);
}
