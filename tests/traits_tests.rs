mod expose_secret_tests {

    #[cfg(feature = "rand")]
    use secure_gate::random::{DynamicRandom, FixedRandom};

    #[cfg(feature = "encoding-hex")]
    use secure_gate::encoding::hex::HexString;

    #[cfg(feature = "encoding-base64")]
    use secure_gate::encoding::base64::Base64String;

    #[cfg(feature = "encoding-bech32")]
    use secure_gate::encoding::bech32::Bech32String;

    #[test]
    fn test_fixed_read_only() {
        let secret = secure_gate::Fixed::new([1u8, 2, 3, 4]);
        let exposed: &[u8; 4] = secret.expose_secret();
        assert_eq!(exposed, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_dynamic_read_only() {
        let secret = secure_gate::Dynamic::new(vec![1u8, 2, 3, 4]);
        let exposed: &[u8] = secret.expose_secret();
        assert_eq!(exposed, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_fixed_mutable() {
        let mut secret = secure_gate::Fixed::new([1u8, 2, 3, 4]);
        {
            let exposed: &mut [u8; 4] = secret.expose_secret_mut();
            exposed[0] = 42;
        }
        assert_eq!(secret.expose_secret(), &[42, 2, 3, 4]);
    }

    #[test]
    fn test_dynamic_mutable() {
        let mut secret = secure_gate::Dynamic::new(vec![1u8, 2, 3, 4]);
        {
            let exposed: &mut Vec<u8> = secret.expose_secret_mut();
            exposed[0] = 42;
        }
        assert_eq!(secret.expose_secret(), &[42, 2, 3, 4]);
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_fixed_random_read_only() {
        let secret = FixedRandom::<32>::generate();
        let exposed: &[u8] = secret.expose_secret();
        assert_eq!(exposed.len(), 32);
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_dynamic_random_read_only() {
        let secret = DynamicRandom::generate(32);
        let exposed: &[u8] = secret.expose_secret();
        assert_eq!(exposed.len(), 32);
    }

    #[cfg(feature = "encoding-hex")]
    #[test]
    fn test_hex_string_read_only() {
        let secret = HexString::new("deadbeef".to_string()).unwrap();
        let exposed: &str = &*secret.expose_secret();
        assert_eq!(exposed, "deadbeef");
    }

    #[cfg(feature = "encoding-base64")]
    #[test]
    fn test_base64_string_read_only() {
        let secret = Base64String::new("ZGVhZGJlZWY".to_string()).unwrap();
        let exposed: &str = &*secret.expose_secret();
        assert_eq!(exposed, "ZGVhZGJlZWY");
    }

    #[cfg(feature = "encoding-bech32")]
    #[test]
    fn test_bech32_string_read_only() {
        let secret =
            Bech32String::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()).unwrap();
        let exposed: &str = &*secret.expose_secret();
        assert!(exposed.contains("bc1q"));
    }
}

mod secure_metadata_tests {
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
}

#[cfg(feature = "rand")]
mod secure_random_tests {
    use secure_gate::{
        random::{DynamicRandom, FixedRandom},
        SecureRandom,
    };

    #[test]
    fn test_fixed_random_trait() {
        let secret = FixedRandom::<32>::generate();

        // Test that it implements both traits
        fn test_random<T: SecureRandom>(_: &T) {}
        test_random(&secret);

        // Test combined functionality
        assert_eq!(secret.len(), 32);
        assert!(!secret.is_empty());
        let data = secret.expose_secret();
        assert_eq!(data.len(), 32);
    }

    #[test]
    fn test_dynamic_random_trait() {
        let secret = DynamicRandom::generate(64);

        fn test_random<T: SecureRandom>(_: &T) {}
        test_random(&secret);

        assert_eq!(secret.len(), 64);
        let data = secret.expose_secret();
        assert_eq!(data.len(), 64);
    }
}

mod polymorphism_tests {
    use secure_gate::{ExposeSecret, SecureMetadata};

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
        fn set_value<T: ExposeSecret<Inner = [u8; 5]>>(item: &mut T, value: [u8; 5]) {
            *item.expose_secret_mut() = value;
        }

        let mut fixed: secure_gate::Fixed<[u8; 5]> = secure_gate::Fixed::new([0u8; 5]);
        set_value(&mut fixed, [1, 2, 3, 4, 5]);
        assert_eq!(fixed.expose_secret(), &[1, 2, 3, 4, 5]);
    }
}
