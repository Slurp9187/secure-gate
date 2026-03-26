// Core API tests for `Fixed<T>` and `Dynamic<T>` (`RevealSecret` / `RevealSecretMut`).

#[cfg(feature = "cloneable")]
use secure_gate::CloneableSecret;
#[cfg(feature = "alloc")]
use secure_gate::Dynamic;
use secure_gate::{RevealSecret, RevealSecretMut, Fixed};

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

#[test]
fn fixed_mutation() {
    let mut key = Fixed::new([0u8; 4]);
    key.with_secret_mut(|s| s[0] = 42);
    key.with_secret(|s| assert_eq!(s, &[42, 0, 0, 0]));
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
#[test]
fn fixed_try_from_slice() {
    let slice: &[u8] = &[1u8, 2, 3, 4];
    let result: Result<Fixed<[u8; 4]>, _> = slice.try_into();
    assert!(result.is_ok());
    let fixed = result.unwrap();
    fixed.with_secret(|s| assert_eq!(s, &[1, 2, 3, 4]));

    let short_slice: &[u8] = &[1u8, 2];
    let _fail: Result<Fixed<[u8; 4]>, _> = short_slice.try_into();
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

    // Wrapper-level clone: Fixed<CloneKey> exposes Clone when CloneableSecret is
    // implemented, and the clone owns independent heap memory (deep clone semantics).
    // If the clone were shallow (shared Vec backing), one of the two sequential drops
    // below would corrupt the other, causing UB or a panic in CloneKey::zeroize.
    let w: Fixed<CloneKey> = Fixed::new(CloneKey(vec![0xBBu8; 4]));
    let w2 = w.clone();
    drop(w);  // zeroizes w's Vec<u8> backing via CloneKey::zeroize
    drop(w2); // independently zeroizes w2's backing — no UB/panic = independent
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

#[cfg(feature = "rand")]
#[test]
fn fixed_from_rng_seeded_deterministic() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    let mut rng_a = StdRng::from_seed([1u8; 32]);
    let mut rng_b = StdRng::from_seed([1u8; 32]);
    let key_a: Fixed<[u8; 16]> = Fixed::from_rng(&mut rng_a).expect("rng fill");
    let key_b: Fixed<[u8; 16]> = Fixed::from_rng(&mut rng_b).expect("rng fill");
    key_a.with_secret(|a| key_b.with_secret(|b| assert_eq!(a, b, "same seed must yield same bytes")));
}

#[cfg(feature = "rand")]
#[cfg(feature = "alloc")]
#[test]
fn dynamic_from_rng_seeded() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use secure_gate::Dynamic;

    let mut rng = StdRng::from_seed([9u8; 32]);
    let a: Dynamic<Vec<u8>> = Dynamic::from_rng(32, &mut rng).expect("rng fill");
    let b: Dynamic<Vec<u8>> = Dynamic::from_rng(32, &mut rng).expect("rng fill");
    a.with_secret(|sa| {
        b.with_secret(|sb| assert_ne!(sa, sb, "sequential draws from same RNG should differ"));
    });
}

// === new_with Construction ===

#[test]
fn fixed_new_with_fills_correctly() {
    let key = Fixed::<[u8; 4]>::new_with(|arr| arr.copy_from_slice(&[1, 2, 3, 4]));
    key.with_secret(|s| assert_eq!(s, &[1u8, 2, 3, 4]));
}

#[test]
fn fixed_new_with_zero_initialized_before_closure() {
    // Closure does nothing — array must be zero, not garbage
    let key = Fixed::<[u8; 8]>::new_with(|_arr| {});
    key.with_secret(|s| assert_eq!(s, &[0u8; 8]));
}

#[test]
fn fixed_new_with_partial_fill() {
    let key = Fixed::<[u8; 4]>::new_with(|arr| arr[0] = 0xFF);
    key.with_secret(|s| {
        assert_eq!(s[0], 0xFF);
        assert_eq!(&s[1..], &[0u8; 3]); // rest stays zero
    });
}

#[test]
fn fixed_new_with_is_zero_cost() {
    let key = Fixed::<[u8; 32]>::new_with(|arr| arr.fill(0xAB));
    assert_eq!(core::mem::size_of_val(&key), 32);
}

// Shared failing RNG for error-propagation tests.
#[cfg(feature = "rand")]
struct FailingRng;

// rand 0.10 requires TryRng::Error: core::error::Error, so &'static str is not enough.
#[cfg(feature = "rand")]
#[derive(Debug)]
struct RngError;

#[cfg(feature = "rand")]
impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("simulated RNG failure")
    }
}

#[cfg(feature = "rand")]
impl std::error::Error for RngError {}

#[cfg(feature = "rand")]
impl rand::TryRng for FailingRng {
    type Error = RngError;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> { Err(RngError) }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> { Err(RngError) }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> { Err(RngError) }
}

#[cfg(feature = "rand")]
impl rand::TryCryptoRng for FailingRng {}

#[cfg(feature = "rand")]
#[test]
fn fixed_from_rng_error_returns_err() {
    let result = Fixed::<[u8; 4]>::from_rng(&mut FailingRng);
    assert!(result.is_err());
}

#[cfg(feature = "alloc")]
#[test]
fn dynamic_vec_new_with_fills_correctly() {
    use secure_gate::Dynamic;
    let secret = Dynamic::<Vec<u8>>::new_with(|v| v.extend_from_slice(&[10, 20, 30]));
    secret.with_secret(|s| assert_eq!(s.as_slice(), &[10u8, 20, 30]));
}

#[cfg(feature = "alloc")]
#[test]
fn dynamic_vec_new_with_empty_closure() {
    use secure_gate::Dynamic;
    let secret = Dynamic::<Vec<u8>>::new_with(|_v| {});
    secret.with_secret(|s| assert!(s.is_empty()));
}

#[cfg(feature = "alloc")]
#[test]
fn dynamic_string_new_with_fills_correctly() {
    use secure_gate::Dynamic;
    let secret = Dynamic::<String>::new_with(|s| s.push_str("hunter2"));
    secret.with_secret(|s| assert_eq!(s.as_str(), "hunter2"));
}

#[cfg(feature = "alloc")]
#[test]
fn dynamic_string_new_with_empty_closure() {
    use secure_gate::Dynamic;
    let secret = Dynamic::<String>::new_with(|_s| {});
    secret.with_secret(|s| assert!(s.is_empty()));
}

#[cfg(feature = "rand")]
#[cfg(feature = "alloc")]
#[test]
fn dynamic_from_rng_error_returns_err() {
    use secure_gate::Dynamic;
    let result = Dynamic::<Vec<u8>>::from_rng(32, &mut FailingRng);
    assert!(result.is_err());
}
