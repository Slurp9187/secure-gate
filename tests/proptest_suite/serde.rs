//! proptests/serde.rs — serde round-trip property tests

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
mod tests {
    use proptest::prelude::*;
    use secure_gate::{Dynamic, Fixed, RevealSecret, SerializableSecret};

    #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
    struct SerializableVec(Vec<u8>);
    impl SerializableSecret for SerializableVec {}

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Inner type round-trip — verifies the inner-type serde contract
        /// independently of the wrapper.
        #[test]
        fn serializable_vec_roundtrip(data in prop::collection::vec(any::<u8>(), 0..=1024)) {
            let value = SerializableVec(data.clone());
            let json = serde_json::to_string(&value).expect("serialize");
            let decoded: SerializableVec = serde_json::from_str(&json).expect("deserialize");
            prop_assert_eq!(decoded.0, data);
        }

        /// Fixed<[u8;32]> deserialization round-trip — exercises the FixedVisitor
        /// (seq → length-check → array copy) with truly random data.
        ///
        /// Serializes the raw array directly ([u8;32] does not implement
        /// SerializableSecret by design) then deserializes into the wrapper.
        #[test]
        fn fixed_array_roundtrip(data in prop::array::uniform32(any::<u8>())) {
            let json = serde_json::to_string(&data).expect("serialize");
            let decoded: Fixed<[u8; 32]> = serde_json::from_str(&json).expect("deserialize");
            prop_assert_eq!(decoded.expose_secret(), &data);
        }

        /// Dynamic<Vec<u8>> deserialization round-trip — exercises the concrete
        /// Deserialize impl on Dynamic<Vec<u8>> with arbitrary payloads.
        ///
        /// Serializes the raw Vec<u8> directly (Vec<u8> does not implement
        /// SerializableSecret by design), then deserializes into the wrapper.
        #[test]
        fn dynamic_vec_roundtrip(data in prop::collection::vec(any::<u8>(), 0..=1024)) {
            let json = serde_json::to_string(&data).expect("serialize");
            let decoded: Dynamic<Vec<u8>> = serde_json::from_str(&json).expect("deserialize");
            prop_assert_eq!(decoded.expose_secret().as_slice(), data.as_slice());
        }

        /// Dynamic<String> deserialization round-trip — exercises the concrete
        /// Deserialize impl on Dynamic<String> with arbitrary printable ASCII strings.
        ///
        /// Uses printable ASCII (0x20–0x7e) to avoid JSON control-character
        /// escaping complexity while still exercising variable-length payloads.
        #[test]
        fn dynamic_string_roundtrip(s in "[\\x20-\\x7e]{0,512}") {
            let json = serde_json::to_string(&s).expect("serialize");
            let decoded: Dynamic<String> = serde_json::from_str(&json).expect("deserialize");
            prop_assert_eq!(decoded.expose_secret().as_str(), s.as_str());
        }

        /// deserialize_with_limit boundary property — the security-critical
        /// accept/reject invariant: data.len() <= limit must succeed,
        /// data.len() > limit must fail.
        #[test]
        fn dynamic_vec_deserialize_limit_boundary(
            data in prop::collection::vec(any::<u8>(), 0..=64),
            limit in 0usize..=64
        ) {
            let json = serde_json::to_string(&data).expect("serialize");
            let mut de = serde_json::Deserializer::from_str(&json);
            let result = Dynamic::<Vec<u8>>::deserialize_with_limit(&mut de, limit);
            if data.len() <= limit {
                prop_assert!(result.is_ok());
            } else {
                prop_assert!(result.is_err());
            }
        }
    }
}
