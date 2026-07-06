//! serde_suite/deserialize.rs — serde deserialize coverage

#[cfg(feature = "serde-deserialize")]
#[test]
fn fixed_deserialize_from_array() {
    use secure_gate::{Fixed, RevealSecret};
    let result: Fixed<[u8; 4]> = serde_json::from_str("[1,2,3,4]").expect("deserialize");
    assert_eq!(result.expose_secret(), &[1, 2, 3, 4]);
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_deserialize_from_array() {
    use secure_gate::{Dynamic, RevealSecret};
    let result: Dynamic<Vec<u8>> = serde_json::from_str("[1,2,3,4]").expect("deserialize");
    assert_eq!(result.expose_secret(), &[1, 2, 3, 4]);
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_deserialize_from_string() {
    use secure_gate::{Dynamic, RevealSecret};
    let result: Dynamic<String> = serde_json::from_str("\"hello\"").expect("deserialize");
    assert_eq!(result.expose_secret(), "hello");
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn fixed_deserialize_wrong_length() {
    use secure_gate::Fixed;
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("[1,2,3]");
    assert!(result.is_err());
}

/// `Fixed<[u8; N]>` also accepts byte-string input (`visit_bytes`) so
/// self-describing formats that encode byte arrays as byte strings (e.g. CBOR)
/// round-trip. `BytesDeserializer` drives the visitor through `visit_bytes`.
#[cfg(feature = "serde-deserialize")]
#[test]
fn fixed_deserialize_from_bytes() {
    use secure_gate::{Fixed, RevealSecret};
    use serde::de::value::{BytesDeserializer, Error as ValueError};

    let de: BytesDeserializer<ValueError> = BytesDeserializer::new(&[1, 2, 3, 4]);
    let result: Fixed<[u8; 4]> = serde::Deserialize::deserialize(de).expect("bytes deserialize");
    assert_eq!(result.expose_secret(), &[1, 2, 3, 4]);

    // Wrong lengths are rejected.
    let de: BytesDeserializer<ValueError> = BytesDeserializer::new(&[1, 2, 3]);
    let short: Result<Fixed<[u8; 4]>, _> = serde::Deserialize::deserialize(de);
    assert!(short.is_err());
    let de: BytesDeserializer<ValueError> = BytesDeserializer::new(&[1, 2, 3, 4, 5]);
    let long: Result<Fixed<[u8; 4]>, _> = serde::Deserialize::deserialize(de);
    assert!(long.is_err());
}

/// `visit_byte_buf` (owned buffer hand-off) is accepted too; the visitor wraps
/// the deserializer-provided buffer in `Zeroizing` before copying, so it is
/// wiped rather than dropped as plain heap memory.
#[cfg(feature = "serde-deserialize")]
#[test]
fn fixed_deserialize_from_byte_buf() {
    use secure_gate::{Fixed, RevealSecret};

    /// Minimal deserializer that hands the visitor an owned `Vec<u8>`,
    /// mirroring formats that produce `visit_byte_buf`.
    struct ByteBufDeserializer(Vec<u8>);
    impl<'de> serde::Deserializer<'de> for ByteBufDeserializer {
        type Error = serde::de::value::Error;
        fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            visitor.visit_byte_buf(self.0)
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map struct enum identifier ignored_any
        }
    }

    let result: Fixed<[u8; 4]> =
        serde::Deserialize::deserialize(ByteBufDeserializer(vec![9, 8, 7, 6]))
            .expect("byte_buf deserialize");
    assert_eq!(result.expose_secret(), &[9, 8, 7, 6]);

    let wrong: Result<Fixed<[u8; 4]>, _> =
        serde::Deserialize::deserialize(ByteBufDeserializer(vec![9, 8, 7]));
    assert!(wrong.is_err());
}

/// Regression: over-length sequences must be rejected *before* the visitor's
/// buffer grows past its reserved capacity. Growing would reallocate and free
/// the old buffer — already holding N secret bytes — without zeroization.
#[cfg(feature = "serde-deserialize")]
#[test]
fn fixed_deserialize_over_length_rejected() {
    use secure_gate::Fixed;
    // One element too many.
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("[1,2,3,4,5]");
    assert!(result.is_err());
    // Grossly over-length input is rejected on the (N+1)-th element, without
    // accumulating the remainder.
    let big = format!("[{}]", vec!["7"; 10_000].join(","));
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str(&big);
    assert!(result.is_err());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_vec_deserialize_malformed_input_returns_err() {
    use secure_gate::Dynamic;
    let result: Result<Dynamic<Vec<u8>>, _> = serde_json::from_str("\"not-an-array\"");
    assert!(result.is_err());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_string_deserialize_roundtrip() {
    use secure_gate::{Dynamic, RevealSecret};
    let result: Dynamic<String> = serde_json::from_str("\"hello world\"").expect("deserialize");
    assert_eq!(result.expose_secret(), "hello world");
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_string_deserialize_malformed_input_returns_err() {
    use secure_gate::Dynamic;
    let result: Result<Dynamic<String>, _> = serde_json::from_str("[1,2,3]");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// deserialize_with_limit — custom ceiling tests
// ---------------------------------------------------------------------------

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_vec_deserialize_with_limit_accepts_within_limit() {
    use secure_gate::{Dynamic, RevealSecret};
    let mut de = serde_json::Deserializer::from_str("[1,2,3,4]");
    let result = Dynamic::<Vec<u8>>::deserialize_with_limit(&mut de, 4).expect("within limit");
    assert_eq!(result.expose_secret(), &[1, 2, 3, 4]);
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_vec_deserialize_with_limit_rejects_over_limit() {
    use secure_gate::Dynamic;
    let mut de = serde_json::Deserializer::from_str("[1,2,3,4]");
    let result = Dynamic::<Vec<u8>>::deserialize_with_limit(&mut de, 3);
    assert!(result.is_err());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_string_deserialize_with_limit_accepts_within_limit() {
    use secure_gate::{Dynamic, RevealSecret};
    let mut de = serde_json::Deserializer::from_str("\"hello\"");
    let result = Dynamic::<String>::deserialize_with_limit(&mut de, 5).expect("within limit");
    assert_eq!(result.expose_secret(), "hello");
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_string_deserialize_with_limit_rejects_over_limit() {
    use secure_gate::Dynamic;
    let mut de = serde_json::Deserializer::from_str("\"hello\"");
    let result = Dynamic::<String>::deserialize_with_limit(&mut de, 4);
    assert!(result.is_err());
}
