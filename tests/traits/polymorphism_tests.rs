use secure_gate::{ExposeSecretMut, SecureMetadata};

#[test]
fn test_metadata_polymorphism() {
    // Can use different types polymorphically for metadata
    fn check_length<T: SecureMetadata>(item: &T) -> usize {
        item.len()
    }

    let fixed: secure_gate::Fixed<[u8; 10]> = secure_gate::Fixed::new([1u8; 10]);
    let string_secret: secure_gate::Dynamic<String> =
        secure_gate::Dynamic::new("hello".to_string());

    assert_eq!(check_length(&fixed), 10);
    assert_eq!(check_length(&string_secret), 5);
}

#[test]
fn test_mutable_polymorphism() {
    // Can use different types polymorphically for mutation
    fn set_first_byte<T: ExposeSecretMut<Inner = [u8; 5]>>(item: &mut T, value: [u8; 5]) {
        *item.expose_secret_mut() = value;
    }

    let mut fixed: secure_gate::Fixed<[u8; 5]> = secure_gate::Fixed::new([0u8; 5]);
    set_first_byte(&mut fixed, [1, 2, 3, 4, 5]);
    assert_eq!(fixed.expose_secret(), &[1, 2, 3, 4, 5]);
}
