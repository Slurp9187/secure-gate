//! proptests/encoding.rs — encoding round-trip property tests

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
mod hex_roundtrip {
    use proptest::prelude::*;
    use secure_gate::{Dynamic, RevealSecret};

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
    use secure_gate::{Dynamic, RevealSecret};

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

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
mod bech32_roundtrip {
    use proptest::prelude::*;
    use secure_gate::{Dynamic, RevealSecret, ToBech32};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn dynamic_bech32_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..=255),
            hrp in "[a-z0-9]{1,10}"
        ) {
            let secret: Dynamic<Vec<u8>> = data.clone().into();
            let encoded = secret.with_secret(|s| s.try_to_bech32(&hrp)).expect("encode");
            let decoded = Dynamic::<Vec<u8>>::try_from_bech32(&encoded, &hrp).expect("decode");
            let decoded_vec = decoded.expose_secret();
            prop_assert_eq!(decoded_vec, data.as_slice());
        }
    }
}

#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
mod bech32m_roundtrip {
    use proptest::prelude::*;
    use secure_gate::{Dynamic, RevealSecret, ToBech32m};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn dynamic_bech32m_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..=90),
            hrp in "[a-z0-9]{1,10}"
        ) {
            let secret: Dynamic<Vec<u8>> = data.clone().into();
            let encoded = secret.with_secret(|s| s.try_to_bech32m(&hrp)).expect("encode");
            let decoded = Dynamic::<Vec<u8>>::try_from_bech32m(&encoded, &hrp).expect("decode");
            let decoded_vec = decoded.expose_secret();
            prop_assert_eq!(decoded_vec, data.as_slice());
        }
    }
}
