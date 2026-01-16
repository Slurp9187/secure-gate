#[cfg(feature = "rand")]
use secure_gate::{
    random::{DynamicRandom, FixedRandom},
    SecureRandom,
};

#[cfg(feature = "rand")]
#[test]
fn test_fixed_random_trait() {
    let secret = FixedRandom::<32>::generate();

    // Test that it implements the SecureRandom trait
    fn test_random<T: SecureRandom>(_: &T) {}
    test_random(&secret);

    // Test combined functionality
    assert_eq!(secret.len(), 32);
    assert!(!secret.is_empty());
    let data = secret.expose_secret();
    assert_eq!(data.len(), 32);
}

#[cfg(feature = "rand")]
#[test]
fn test_dynamic_random_trait() {
    let secret = DynamicRandom::generate(64);

    fn test_random<T: SecureRandom>(_: &T) {}
    test_random(&secret);

    assert_eq!(secret.len(), 64);
    let data = secret.expose_secret();
    assert_eq!(data.len(), 64);
}
