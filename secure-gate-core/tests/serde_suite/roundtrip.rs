//! serde_suite/roundtrip.rs — serde serialize/deserialize roundtrip coverage

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
use secure_gate::SerializableSecret;

// ---------------------------------------------------------------------------
// Inner types (raw) — test the inner-type serde contract
// ---------------------------------------------------------------------------

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[derive(serde::Serialize, serde::Deserialize)]
struct TestSerializableArray([u8; 4]);

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
impl SerializableSecret for TestSerializableArray {}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[derive(serde::Serialize, serde::Deserialize)]
struct TestSerializableVec(Vec<u8>);

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
impl SerializableSecret for TestSerializableVec {}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn fixed_roundtrip() {
    let original = TestSerializableArray([1u8, 2, 3, 4]);
    let serialized = serde_json::to_string(&original).expect("serialize");
    let deserialized: TestSerializableArray =
        serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(original.0, deserialized.0);
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn dynamic_roundtrip() {
    let original = TestSerializableVec(vec![1u8, 2, 3, 4]);
    let serialized = serde_json::to_string(&original).expect("serialize");
    let deserialized: TestSerializableVec = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(original.0, deserialized.0);
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn fixed_binary_roundtrip_bincode() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct SerializableArray32([u8; 32]);
    impl SerializableSecret for SerializableArray32 {}

    let original = SerializableArray32([0xab; 32]);
    let config = bincode::config::standard();
    let bytes = bincode::serde::encode_to_vec(&original, config).expect("serialize");
    let (round, _): (SerializableArray32, _) =
        bincode::serde::decode_from_slice(&bytes, config).expect("deserialize");
    assert_eq!(original.0, round.0);
}

// ---------------------------------------------------------------------------
// Wrapper types — test Fixed<T> / Dynamic<T> with the serde contract.
//
// Design note: Fixed<T>::Deserialize is only implemented for Fixed<[u8; N]>
// (hardcoded array format). Dynamic<T>::Deserialize is only implemented for
// Dynamic<String> and Dynamic<Vec<u8>>. Because of this, full roundtrip tests
// for wrapper types with custom inner types are not possible without modifying
// the crate. What we CAN test:
//   - Fixed<T> and Dynamic<T> SERIALIZE correctly (transparent delegation)
//   - Debug output stays [REDACTED] even with serde-serialize enabled
//   - The serialized JSON matches the expected inner-type format
// ---------------------------------------------------------------------------

/// Fixed<T: SerializableSecret + Zeroize + Serialize> delegates serialization
/// to the inner value. Verifies the wrapper participates in the serde chain
/// and that debug redaction is preserved with the serde-serialize feature active.
#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn fixed_wrapper_serializes_correctly() {
    use secure_gate::Fixed;

    #[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize)]
    struct SecretKey([u8; 4]);
    impl SerializableSecret for SecretKey {}

    let secret = Fixed::new(SecretKey([10, 20, 30, 40]));
    // Security invariant: debug redaction must hold even with serde-serialize enabled.
    crate::common::assert_redacted_debug(&secret);
    let json = serde_json::to_string(&secret).expect("serialize Fixed<SecretKey>");
    // The wrapper serializes transparently — verify by parsing the raw bytes back.
    let raw: Vec<u8> = serde_json::from_str(&json).expect("parse JSON");
    assert_eq!(raw, [10, 20, 30, 40]);
}

/// Dynamic<T: SerializableSecret + Zeroize + Serialize> delegates serialization
/// to the inner value. Verifies the wrapper serializes correctly.
#[cfg(all(
    feature = "serde-deserialize",
    feature = "serde-serialize",
    feature = "alloc"
))]
#[test]
fn dynamic_wrapper_serializes_correctly() {
    use secure_gate::Dynamic;

    #[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize)]
    struct SecretPayload(Vec<u8>);
    impl SerializableSecret for SecretPayload {}

    let secret = Dynamic::new(SecretPayload(vec![5u8, 6, 7, 8]));
    // Security invariant: debug redaction must hold even with serde-serialize enabled.
    crate::common::assert_redacted_debug(&secret);
    let json = serde_json::to_string(&secret).expect("serialize Dynamic<SecretPayload>");
    // The wrapper serializes transparently — verify by parsing the raw bytes back.
    let raw: Vec<u8> = serde_json::from_str(&json).expect("parse JSON");
    assert_eq!(raw, [5, 6, 7, 8]);
}

// ---------------------------------------------------------------------------
// Full wrapper round-trips: serialize Fixed/Dynamic → JSON → deserialize back
// ---------------------------------------------------------------------------

/// Fixed<[u8; N]> serde round-trip: serialize the raw array, deserialize into
/// the Fixed wrapper, then verify inner data matches. This exercises the
/// FixedVisitor deserialization path with known data.
#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn fixed_wrapper_serde_roundtrip() {
    use secure_gate::{Fixed, RevealSecret};

    let data = [0xAAu8, 0xBB, 0xCC, 0xDD];
    let json = serde_json::to_string(&data).expect("serialize raw array");
    let restored: Fixed<[u8; 4]> = serde_json::from_str(&json).expect("deserialize Fixed<[u8; 4]>");
    assert_eq!(restored.expose_secret(), &data);
}

/// Dynamic<Vec<u8>> serde round-trip: serialize the raw Vec, deserialize into
/// the Dynamic wrapper, then verify inner data matches.
#[cfg(all(
    feature = "serde-deserialize",
    feature = "serde-serialize",
    feature = "alloc"
))]
#[test]
fn dynamic_vec_wrapper_serde_roundtrip() {
    use secure_gate::{Dynamic, RevealSecret};

    let data = vec![1u8, 2, 3, 4, 5];
    let json = serde_json::to_string(&data).expect("serialize raw Vec");
    let restored: Dynamic<Vec<u8>> =
        serde_json::from_str(&json).expect("deserialize Dynamic<Vec<u8>>");
    assert_eq!(restored.expose_secret().as_slice(), data.as_slice());
}

/// Dynamic<String> serde round-trip: serialize the raw String, deserialize into
/// the Dynamic wrapper, then verify inner data matches.
#[cfg(all(
    feature = "serde-deserialize",
    feature = "serde-serialize",
    feature = "alloc"
))]
#[test]
fn dynamic_string_wrapper_serde_roundtrip() {
    use secure_gate::{Dynamic, RevealSecret};

    let data = String::from("round_trip_secret");
    let json = serde_json::to_string(&data).expect("serialize raw String");
    let restored: Dynamic<String> =
        serde_json::from_str(&json).expect("deserialize Dynamic<String>");
    assert_eq!(restored.expose_secret().as_str(), data.as_str());
}

/// Full wrapper-to-wrapper round-trip for a custom SerializableSecret type.
/// Serializes Fixed<SecretKey> → JSON → deserializes back (as raw) → verifies.
#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
#[test]
fn fixed_custom_type_serialize_then_deserialize_raw() {
    use secure_gate::{Fixed, RevealSecret};

    #[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize)]
    struct Key([u8; 4]);
    impl SerializableSecret for Key {}

    let secret = Fixed::new(Key([0x10, 0x20, 0x30, 0x40]));
    let json = serde_json::to_string(&secret).expect("serialize Fixed<Key>");
    // The serialized form is the inner array — deserialize as Fixed<[u8; 4]>.
    let restored: Fixed<[u8; 4]> = serde_json::from_str(&json).expect("deserialize Fixed<[u8; 4]>");
    assert_eq!(restored.expose_secret(), &[0x10, 0x20, 0x30, 0x40]);
}
