//! proptests/serde.rs — serde round-trip property tests

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
mod tests {
    use proptest::prelude::*;
    use secure_gate::{Fixed, SerializableSecret};

    #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
    struct SerializableVec(Vec<u8>);
    impl SerializableSecret for SerializableVec {}

    /// Fixed<T: SerializableSecret + Zeroize + Serialize> serializes transparently.
    /// Verifies that Fixed<T> produces the expected inner-type JSON under arbitrary data.
    #[derive(serde::Serialize, serde::Deserialize, Clone, Debug, zeroize::Zeroize)]
    struct SerializableKey([u8; 4]);
    impl SerializableSecret for SerializableKey {}

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn serializable_vec_roundtrip(data in prop_oneof![
            Just(vec![]),
            prop::collection::vec(any::<u8>(), 1..=1),
            Just(vec![0xAAu8; 127]),
            prop::collection::vec(any::<u8>(), 0usize..128),
        ]) {
            let value = SerializableVec(data.clone());
            let json = serde_json::to_string(&value).expect("serialize");
            let decoded: SerializableVec = serde_json::from_str(&json).expect("deserialize");
            prop_assert_eq!(decoded.0, data);
        }

        /// Fixed<T> wrapper serializes transparently to the inner value's JSON format.
        /// Parses the JSON back as Vec<u8> to verify byte-level correctness.
        #[test]
        fn fixed_wrapper_serializes_correctly(
            b0 in any::<u8>(),
            b1 in any::<u8>(),
            b2 in any::<u8>(),
            b3 in any::<u8>()
        ) {
            let secret = Fixed::new(SerializableKey([b0, b1, b2, b3]));
            let json = serde_json::to_string(&secret).expect("serialize Fixed wrapper");
            // Verify transparent delegation by parsing raw bytes from JSON.
            let raw: Vec<u8> = serde_json::from_str(&json).expect("parse JSON");
            prop_assert_eq!(raw, vec![b0, b1, b2, b3]);
        }
    }
}
