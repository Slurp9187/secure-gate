#[allow(unused_imports)]
use secure_gate::SecureMetadata;

#[cfg(feature = "rand")]
use secure_gate::random::{DynamicRandom, FixedRandom};

#[cfg(feature = "zeroize")]
use secure_gate::cloneable::{CloneableArray, CloneableString, CloneableVec};

#[cfg(feature = "encoding-hex")]
use secure_gate::encoding::hex::HexString;

#[test]
fn test_fixed_metadata() {
    let secret = secure_gate::Fixed::new([1u8; 32]);
    assert_eq!(secret.len(), 32);
    assert!(!secret.is_empty());

    let empty = secure_gate::Fixed::new([]);
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}

#[test]
fn test_dynamic_string_metadata() {
    let secret: secure_gate::Dynamic<String> = secure_gate::Dynamic::new("hello".to_string());
    assert_eq!(secret.len(), 5);
    assert!(!secret.is_empty());
}

#[test]
fn test_dynamic_vec_metadata() {
    let secret: secure_gate::Dynamic<Vec<u8>> = secure_gate::Dynamic::new(vec![1u8, 2, 3]);
    assert_eq!(secret.len(), 3);
    assert!(!secret.is_empty());
}

#[cfg(feature = "rand")]
#[test]
fn test_random_metadata() {
    let fixed = FixedRandom::<16>::generate();
    assert_eq!(fixed.len(), 16);

    let dynamic = DynamicRandom::generate(24);
    assert_eq!(dynamic.len(), 24);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_hex_metadata() {
    let secret = HexString::new("deadbeef".to_string()).unwrap();
    assert_eq!(secret.len(), 8);
    assert!(!secret.is_empty());
}

#[cfg(feature = "zeroize")]
#[test]
fn test_cloneable_metadata() {
    let array: CloneableArray<32> = [42u8; 32].into();
    assert_eq!(array.len(), 32);

    let string: CloneableString = "test".to_string().into();
    assert_eq!(string.len(), 4);

    let vec: CloneableVec = vec![1u8, 2, 3].into();
    assert_eq!(vec.len(), 3);
}
