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

// ---------------------------------------------------------------------------
// deserialize_with_limit — boundary conditions
// ---------------------------------------------------------------------------

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_vec_deserialize_with_limit_zero_accepts_empty() {
    use secure_gate::{Dynamic, RevealSecret};
    let mut de = serde_json::Deserializer::from_str("[]");
    let result =
        Dynamic::<Vec<u8>>::deserialize_with_limit(&mut de, 0).expect("empty within limit 0");
    assert!(result.expose_secret().is_empty());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_vec_deserialize_with_limit_zero_rejects_nonempty() {
    use secure_gate::Dynamic;
    let mut de = serde_json::Deserializer::from_str("[1]");
    let result = Dynamic::<Vec<u8>>::deserialize_with_limit(&mut de, 0);
    assert!(result.is_err());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_string_deserialize_with_limit_zero_accepts_empty() {
    use secure_gate::{Dynamic, RevealSecret};
    let mut de = serde_json::Deserializer::from_str("\"\"");
    let result =
        Dynamic::<String>::deserialize_with_limit(&mut de, 0).expect("empty within limit 0");
    assert!(result.expose_secret().is_empty());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_string_deserialize_with_limit_zero_rejects_nonempty() {
    use secure_gate::Dynamic;
    let mut de = serde_json::Deserializer::from_str("\"a\"");
    let result = Dynamic::<String>::deserialize_with_limit(&mut de, 0);
    assert!(result.is_err());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_vec_deserialize_with_limit_one() {
    use secure_gate::{Dynamic, RevealSecret};
    let mut de = serde_json::Deserializer::from_str("[42]");
    let result = Dynamic::<Vec<u8>>::deserialize_with_limit(&mut de, 1)
        .expect("single element within limit 1");
    assert_eq!(result.expose_secret(), &[42u8]);
}

// === 0.9.1: the secret is read into a wiped buffer (#249), and `Dynamic<[u8]>` (#267) ===

/// A secret longer than any single growth step still arrives whole and in order: the
/// hand-written growth (allocate, copy, wipe the old buffer) must not lose or reorder bytes.
#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_vec_deserialize_survives_every_growth_step() {
    use secure_gate::{Dynamic, RevealSecret};
    for len in [0usize, 1, 63, 64, 65, 127, 128, 129, 1008, 5000] {
        let want: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let json = serde_json::to_string(&want).unwrap();
        let got: Dynamic<Vec<u8>> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(got.expose_secret(), &want, "length {len}");
    }
}

/// A `size_hint` is a request from the input. A sequence that announces far more than it
/// holds must not make this crate allocate what it announced: the first buffer is capped
/// (4096 bytes), whatever the hint and however large the limit.
#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_vec_deserialize_does_not_trust_the_size_hint() {
    use secure_gate::{Dynamic, RevealSecret};
    use serde::de::value::{Error as ValueError, SeqAccessDeserializer};
    use serde::de::{DeserializeSeed, SeqAccess};

    /// Three bytes that claim to be `usize::MAX`.
    struct Liar(std::vec::IntoIter<u8>);
    impl<'de> SeqAccess<'de> for Liar {
        type Error = ValueError;
        fn next_element_seed<T: DeserializeSeed<'de>>(
            &mut self,
            seed: T,
        ) -> Result<Option<T::Value>, ValueError> {
            use serde::de::IntoDeserializer;
            self.0
                .next()
                .map(|b| seed.deserialize(b.into_deserializer()))
                .transpose()
        }
        fn size_hint(&self) -> Option<usize> {
            Some(usize::MAX)
        }
    }

    let de = SeqAccessDeserializer::new(Liar(vec![1, 2, 3].into_iter()));
    let got = Dynamic::<Vec<u8>>::deserialize_with_limit(de, 1_000_000).expect("three bytes");
    assert_eq!(got.expose_secret(), &[1, 2, 3]);
    // The wrapper holds the buffer the bytes were read into, so its capacity is what the
    // hint was allowed to allocate.
    assert!(
        got.expose_secret().capacity() <= 4096,
        "a hostile size hint allocated {} bytes",
        got.expose_secret().capacity()
    );

    // And a hint is never allowed past the limit either.
    let de = SeqAccessDeserializer::new(Liar(vec![1, 2, 3].into_iter()));
    let got = Dynamic::<Vec<u8>>::deserialize_with_limit(de, 8).expect("three bytes");
    assert!(got.expose_secret().capacity() <= 8);
}

/// A truthful hint is honoured up to the limit, and the limit is exact.
#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_vec_deserialize_limit_is_exact_for_a_hinted_sequence() {
    use secure_gate::{Dynamic, RevealSecret};
    use serde::de::value::{Error as ValueError, SeqDeserializer};

    let de: SeqDeserializer<_, ValueError> =
        SeqDeserializer::new((0u8..200).collect::<Vec<_>>().into_iter());
    let got = Dynamic::<Vec<u8>>::deserialize_with_limit(de, 200).expect("at the limit");
    assert_eq!(got.expose_secret().len(), 200);

    let de: SeqDeserializer<_, ValueError> =
        SeqDeserializer::new((0u8..200).collect::<Vec<_>>().into_iter());
    assert!(Dynamic::<Vec<u8>>::deserialize_with_limit(de, 199).is_err());
}

/// `Dynamic<Vec<u8>>` accepts what `Vec<u8>` accepts and nothing more: a JSON string is
/// still refused, with serde's own wording.
#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_vec_deserialize_still_refuses_a_string() {
    use secure_gate::Dynamic;
    let plain = serde_json::from_str::<Vec<u8>>("\"abc\"")
        .unwrap_err()
        .to_string();
    let ours = serde_json::from_str::<Dynamic<Vec<u8>>>("\"abc\"")
        .unwrap_err()
        .to_string();
    assert_eq!(ours, plain);
}

/// Owned text (`visit_string`) and text sent as bytes are accepted as `String` accepts
/// them; bytes that are not UTF-8 are refused.
#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_string_deserialize_from_owned_and_bytes() {
    use secure_gate::{Dynamic, RevealSecret};
    use serde::de::value::{BytesDeserializer, Error as ValueError, StringDeserializer};

    let de: StringDeserializer<ValueError> = StringDeserializer::new(String::from("pässword"));
    let got: Dynamic<String> = serde::Deserialize::deserialize(de).expect("owned string");
    assert_eq!(got.expose_secret(), "pässword");

    let de: StringDeserializer<ValueError> = StringDeserializer::new(String::from("too long"));
    assert!(Dynamic::<String>::deserialize_with_limit(de, 7).is_err());

    let de: BytesDeserializer<ValueError> = BytesDeserializer::new(b"abc");
    let got: Dynamic<String> = serde::Deserialize::deserialize(de).expect("utf-8 bytes");
    assert_eq!(got.expose_secret(), "abc");

    let de: BytesDeserializer<ValueError> = BytesDeserializer::new(&[0xFF, 0xFE]);
    assert!(<Dynamic<String> as serde::Deserialize>::deserialize(de).is_err());
}

/// A string with escapes goes through the deserializer's scratch buffer and still arrives
/// intact, in a buffer of exactly its length.
#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_string_deserialize_is_exactly_sized() {
    use secure_gate::{Dynamic, RevealSecret};
    let got: Dynamic<String> = serde_json::from_str(r#""a\"b\né""#).expect("escapes");
    assert_eq!(got.expose_secret(), "a\"b\n\u{e9}");
    assert_eq!(got.expose_secret().capacity(), got.expose_secret().len());
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_slice_deserialize_and_len() {
    use secure_gate::{Dynamic, RevealSecret, SecretLen};

    let got: Dynamic<[u8]> = serde_json::from_str("[1,2,3,4]").expect("deserialize");
    assert_eq!(got.expose_secret(), &[1, 2, 3, 4]);
    assert_eq!(got.len(), 4);
    assert_eq!(got.byte_len(), 4);
    assert!(!got.is_empty());

    let empty: Dynamic<[u8]> = serde_json::from_str("[]").expect("empty");
    assert!(empty.is_empty());

    let mut de = serde_json::Deserializer::from_str("[1,2,3,4]");
    assert!(Dynamic::<[u8]>::deserialize_with_limit(&mut de, 3).is_err());
    let mut de = serde_json::Deserializer::from_str("[1,2,3,4]");
    assert!(Dynamic::<[u8]>::deserialize_with_limit(&mut de, 4).is_ok());

    assert!(serde_json::from_str::<Dynamic<[u8]>>("[1,2,300]").is_err());
}
