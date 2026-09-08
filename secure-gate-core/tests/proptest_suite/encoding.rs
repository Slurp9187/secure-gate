//! proptests/encoding.rs — encoding round-trip property tests

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
mod hex_roundtrip {
    use proptest::prelude::*;
    use secure_gate::{Dynamic, RevealSecret, ToHex};

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

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
mod b32_roundtrip {
    use proptest::prelude::*;
    use secure_gate::{Dynamic, RevealSecret, ToBase32};

    // Base32 decoding is lenient about non-canonical trailing bits (D5): distinct
    // strings can decode to the same bytes, so the property must run
    // encode-then-decode. Starting from arbitrary "valid-looking" strings and
    // re-encoding them would not be a round-trip.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn dynamic_b32_roundtrip(data in prop_oneof![
            Just(vec![]),
            prop::collection::vec(any::<u8>(), 1..=1),
            Just(vec![0xAAu8; 127]),
            prop::collection::vec(any::<u8>(), 0usize..128),
        ]) {
            let secret: Dynamic<Vec<u8>> = data.clone().into();
            let encoded = secret.to_base32();
            let decoded = Dynamic::<Vec<u8>>::try_from_base32(&encoded).expect("decode");
            let decoded_vec = decoded.expose_secret();
            prop_assert_eq!(decoded_vec, data.as_slice());
        }
    }
}

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
mod b64_roundtrip {
    use proptest::prelude::*;
    use secure_gate::{Dynamic, RevealSecret, ToBase64Url};

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

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
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

// A code length large enough for every payload these properties generate:
// 3-char HRP + separator + ceil(2048*8/5) + 6 checksum = 3287, rounded up.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
mod bech32_sized_roundtrip {
    use proptest::prelude::*;
    use secure_gate::{BECH32_CODE_LENGTH, Bech32Error, FromBech32Str, ToBech32};

    const BIG: usize = 4096;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Round-trips at a large code length for payloads of every size, including
        /// those far past the default.
        #[test]
        fn sized_roundtrip_any_length(data in prop_oneof![
            Just(vec![]),
            prop::collection::vec(any::<u8>(), 1..=1),
            prop::collection::vec(any::<u8>(), 0usize..64),
            prop::collection::vec(any::<u8>(), 600usize..700),   // straddles the default
            prop::collection::vec(any::<u8>(), 1500usize..1600), // KEM-sized
        ]) {
            let encoded = data.try_to_bech32_sized::<BIG>("age").expect("encodes");
            let decoded = encoded.try_from_bech32_sized::<BIG>("age").expect("decodes");
            prop_assert_eq!(decoded, data);
        }

        /// The code length is a gate, never an input to the checksum: encoding the same
        /// bytes at two different `N` that both admit them yields identical strings.
        #[test]
        fn code_length_does_not_change_the_encoding(
            data in prop::collection::vec(any::<u8>(), 0usize..600)
        ) {
            let at_default = data.try_to_bech32_sized::<BECH32_CODE_LENGTH>("age");
            let at_big = data.try_to_bech32_sized::<BIG>("age");
            match (at_default, at_big) {
                (Ok(a), Ok(b)) => prop_assert_eq!(a, b),
                (Err(_), Ok(_)) => { /* payload needs more than the default: fine */ }
                (a, b) => prop_assert!(false, "unexpected pair: {:?} / {:?}", a, b),
            }
        }

        /// A string longer than the decoder's `N` is refused rather than truncated.
        #[test]
        fn decoder_refuses_strings_longer_than_its_code_length(
            data in prop::collection::vec(any::<u8>(), 700usize..900)
        ) {
            let encoded = data.try_to_bech32_sized::<BIG>("age").expect("encodes");
            prop_assume!(encoded.len() > BECH32_CODE_LENGTH);
            prop_assert_eq!(
                encoded.try_from_bech32("age"),
                Err(Bech32Error::OperationFailed)
            );
        }

        /// HRP validation is unaffected by the code length.
        #[test]
        fn sized_hrp_mismatch_is_always_detected(
            data in prop::collection::vec(any::<u8>(), 0usize..600)
        ) {
            let encoded = data.try_to_bech32_sized::<BIG>("age").expect("encodes");
            prop_assert_eq!(
                encoded.try_from_bech32_sized::<BIG>("kem"),
                Err(Bech32Error::UnexpectedHrp)
            );
        }
    }
}

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
mod bech32m_sized_roundtrip {
    use proptest::prelude::*;
    use secure_gate::{FromBech32mStr, ToBech32m};

    const BIG: usize = 4096;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn sized_roundtrip_any_length(data in prop_oneof![
            Just(vec![]),
            prop::collection::vec(any::<u8>(), 0usize..64),
            prop::collection::vec(any::<u8>(), 600usize..700),
            prop::collection::vec(any::<u8>(), 1500usize..1600),
        ]) {
            let encoded = data.try_to_bech32m_sized::<BIG>("age").expect("encodes");
            let decoded = encoded.try_from_bech32m_sized::<BIG>("age").expect("decodes");
            prop_assert_eq!(decoded, data);
        }
    }
}

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
mod bech32_variants_never_cross {
    use proptest::prelude::*;
    use secure_gate::{FromBech32Str, FromBech32mStr, ToBech32, ToBech32m};

    const BIG: usize = 4096;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// No payload and no code length makes a BIP-173 string decode as BIP-350,
        /// or the reverse. The two differ only in target residue, so this is the
        /// property that a shared const-generic checksum must not break.
        #[test]
        fn checksums_stay_distinct(
            data in prop::collection::vec(any::<u8>(), 0usize..900)
        ) {
            let b32 = data.try_to_bech32_sized::<BIG>("x").expect("bech32");
            let b32m = data.try_to_bech32m_sized::<BIG>("x").expect("bech32m");

            // Identical payloads, different checksums: the strings differ, and
            // neither decodes under the other's algorithm.
            prop_assert_ne!(&b32, &b32m);
            prop_assert!(b32.try_from_bech32m_sized::<BIG>("x").is_err());
            prop_assert!(b32m.try_from_bech32_sized::<BIG>("x").is_err());
        }
    }
}
