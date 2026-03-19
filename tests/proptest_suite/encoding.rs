//! proptests/encoding.rs — encoding round-trip property tests

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
mod hex_roundtrip {
    use proptest::prelude::*;
    use secure_gate::{Dynamic, ExposeSecret};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn dynamic_hex_roundtrip(data in prop_oneof![
            Just(vec![]),
            prop::collection::vec(any::<u8>(), 1..=1),
            Just(vec![0xAAu8; 127]),
            prop::collection::vec(any::<u8>(), 0usize..128),
        ]) {
            let secret: Dynamic<Vec<u8>> = data.clone().into();
            let encoded = secret.to_hex();
            let decoded = Dynamic::<Vec<u8>>::try_from_hex(&encoded).expect("decode");
            let decoded_vec = decoded.expose_secret();
            prop_assert_eq!(decoded_vec, data.as_slice());
        }
    }
}

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
mod b64_roundtrip {
    use proptest::prelude::*;
    use secure_gate::{Dynamic, ExposeSecret};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn dynamic_b64_roundtrip(data in prop_oneof![
            Just(vec![]),
            prop::collection::vec(any::<u8>(), 1..=1),
            Just(vec![0xAAu8; 127]),
            prop::collection::vec(any::<u8>(), 0usize..128),
        ]) {
            let secret: Dynamic<Vec<u8>> = data.clone().into();
            let encoded = secret.to_base64url();
            let decoded = Dynamic::<Vec<u8>>::try_from_base64url(&encoded).expect("decode");
            let decoded_vec = decoded.expose_secret();
            prop_assert_eq!(decoded_vec, data.as_slice());
        }
    }
}
