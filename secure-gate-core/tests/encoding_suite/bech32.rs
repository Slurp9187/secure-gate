//! encoding_suite/bech32.rs — bech32/bech32m encoding/decoding tests

#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
use secure_gate::Bech32Error;
#[cfg(all(any(feature = "encoding-bech32", feature = "encoding-bech32m"), feature = "alloc"))]
use secure_gate::Dynamic;
#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
use secure_gate::RevealSecret;
#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
use secure_gate::Fixed;
#[cfg(feature = "encoding-bech32")]
use secure_gate::{FromBech32Str, ToBech32};
#[cfg(feature = "encoding-bech32m")]
use secure_gate::{FromBech32mStr, ToBech32m};

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_unchecked_roundtrip_preserves_hrp() {
    let data = b"hello world";
    let encoded = data.try_to_bech32("fuzz").expect("valid bech32");

    let (hrp, decoded) = encoded.try_from_bech32_unchecked().expect("valid bech32");
    assert_eq!(hrp, "fuzz");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_to_bech32_zeroizing_matches_plain() {
    let fixed = Fixed::new([1u8, 2, 3, 4]);
    let plain = fixed
        .with_secret(|s| s.try_to_bech32("fuzz"))
        .expect("plain encode");
    let zeroizing = fixed
        .try_to_bech32_zeroizing("fuzz")
        .expect("zeroizing encode");
    assert_eq!(&*zeroizing, plain.as_str());
}

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
#[test]
fn dynamic_try_to_bech32_zeroizing_roundtrip() {
    let secret: Dynamic<Vec<u8>> = vec![9, 8, 7, 6].into();
    let encoded = secret
        .try_to_bech32_zeroizing("dyn")
        .expect("zeroizing encode");
    let encoded_plain = encoded.into_inner();
    let decoded = encoded_plain.as_str().try_from_bech32("dyn").expect("decode");
    assert_eq!(decoded, vec![9, 8, 7, 6]);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_to_bech32_zeroizing_debug_is_redacted() {
    let fixed = Fixed::new([1u8, 2, 3, 4]);
    let encoded = fixed
        .try_to_bech32_zeroizing("fuzz")
        .expect("zeroizing encode");
    assert_eq!(format!("{encoded:?}"), "[REDACTED]");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn slice_try_to_bech32_zeroizing() {
    let encoded = b"hello"
        .try_to_bech32_zeroizing("fuzz")
        .expect("zeroizing encode");
    assert!(encoded.starts_with("fuzz1"));
    assert_eq!(&*encoded, b"hello".try_to_bech32("fuzz").expect("plain encode"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_invalid_hrp_encode_fails() {
    let err = b"data".try_to_bech32("");
    assert_eq!(err, Err(Bech32Error::InvalidHrp));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn try_to_bech32_zeroizing_invalid_hrp_returns_err() {
    let err = b"data".try_to_bech32_zeroizing("");
    assert!(matches!(err, Err(Bech32Error::InvalidHrp)));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn try_to_bech32_zeroizing_empty_bytes() {
    let encoded = b""
        .try_to_bech32_zeroizing("fuzz")
        .expect("empty payload should still encode");
    assert!(!encoded.is_empty());
    assert!(encoded.starts_with("fuzz1"));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_decode_malformed_fails() {
    let err = "notabech32string".try_from_bech32("fuzz");
    assert!(err.is_err());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_try_from_bech32_accepts_matching_hrp() {
    let data = b"hello world";
    let encoded = data.try_to_bech32("fuzz").expect("valid bech32");
    let decoded = encoded
        .try_from_bech32("fuzz")
        .expect("expected hrp should match");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_try_from_bech32_rejects_mismatched_hrp() {
    let data = b"hello world";
    let encoded = data.try_to_bech32("fuzz").expect("valid bech32");
    let err = encoded.try_from_bech32("other");
    assert!(err.is_err());
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bech32m_roundtrip() {
    let data = b"payload";
    let encoded = data.try_to_bech32m("fuzzm").expect("valid");
    let (hrp, decoded) = encoded.try_from_bech32m_unchecked().expect("valid bech32m");
    assert_eq!(hrp, "fuzzm");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_to_bech32m_zeroizing_matches_plain() {
    let fixed = Fixed::new([1u8, 2, 3, 4]);
    let plain = fixed
        .with_secret(|s| s.try_to_bech32m("fuzzm"))
        .expect("plain encode");
    let zeroizing = fixed
        .try_to_bech32m_zeroizing("fuzzm")
        .expect("zeroizing encode");
    assert_eq!(&*zeroizing, plain.as_str());
}

#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
#[test]
fn dynamic_try_to_bech32m_zeroizing_roundtrip() {
    let secret: Dynamic<Vec<u8>> = vec![1, 3, 3, 7].into();
    let encoded = secret
        .try_to_bech32m_zeroizing("dyn")
        .expect("zeroizing encode");
    let encoded_plain = encoded.into_inner();
    let decoded = encoded_plain.as_str().try_from_bech32m("dyn").expect("decode");
    assert_eq!(decoded, vec![1, 3, 3, 7]);
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_to_bech32m_zeroizing_debug_is_redacted() {
    let fixed = Fixed::new([1u8, 2, 3, 4]);
    let encoded = fixed
        .try_to_bech32m_zeroizing("fuzzm")
        .expect("zeroizing encode");
    assert_eq!(format!("{encoded:?}"), "[REDACTED]");
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn slice_try_to_bech32m_zeroizing() {
    let encoded = b"hello"
        .try_to_bech32m_zeroizing("fuzzm")
        .expect("zeroizing encode");
    assert!(encoded.starts_with("fuzzm1"));
    assert_eq!(&*encoded, b"hello".try_to_bech32m("fuzzm").expect("plain encode"));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bech32m_invalid_hrp_encode_fails() {
    let err = b"data".try_to_bech32m("");
    assert_eq!(err, Err(Bech32Error::InvalidHrp));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn try_to_bech32m_zeroizing_invalid_hrp_returns_err() {
    let err = b"data".try_to_bech32m_zeroizing("");
    assert!(matches!(err, Err(Bech32Error::InvalidHrp)));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn try_to_bech32m_zeroizing_data_too_large_returns_err() {
    let err = vec![0u8; 800].try_to_bech32m_zeroizing("fuzzm");
    assert!(matches!(err, Err(Bech32Error::OperationFailed)));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bech32m_decode_malformed_fails() {
    let err = "notabech32mstring".try_from_bech32m("fuzzm");
    assert!(err.is_err());
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bech32m_try_from_bech32m_accepts_matching_hrp() {
    let data = b"hello world";
    let encoded = data.try_to_bech32m("fuzz").expect("valid bech32m");
    let decoded = encoded
        .try_from_bech32m("fuzz")
        .expect("expected hrp should match");
    assert_eq!(decoded, data);
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn bech32m_try_from_bech32m_rejects_mismatched_hrp() {
    let data = b"hello world";
    let encoded = data.try_to_bech32m("fuzz").expect("valid bech32m");
    let err = encoded.try_from_bech32m("other");
    assert!(err.is_err());
}

#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
#[test]
fn dynamic_try_from_bech32m_roundtrip() {
    let data = b"abcd";
    let encoded = data.try_to_bech32m("dyn").expect("valid");
    let dynv = Dynamic::<Vec<u8>>::try_from_bech32m(&encoded, "dyn").expect("decode");
    dynv.with_secret(|d| assert_eq!(d, b"abcd"));
}

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
#[test]
fn dynamic_try_from_bech32_invalid_input_returns_err() {
    assert!(
        secure_gate::Dynamic::<Vec<u8>>::try_from_bech32_unchecked("notabech32string").is_err()
    );
}

#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
#[test]
fn dynamic_try_from_bech32m_invalid_input_returns_err() {
    assert!(Dynamic::<Vec<u8>>::try_from_bech32m_unchecked("notabech32mstring").is_err());
}

// No-alloc decode path tests: Fixed::try_from_bech32 / try_from_bech32m work without alloc feature
#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_roundtrip() {
    use secure_gate::ToBech32;
    let data = [1u8, 2, 3, 4];
    let encoded = data.try_to_bech32("test").expect("encode");
    let decoded = Fixed::<[u8; 4]>::try_from_bech32(&encoded, "test").expect("decode");
    decoded.with_secret(|b| assert_eq!(b, &[1u8, 2, 3, 4]));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_hrp_mismatch_fails() {
    use secure_gate::ToBech32;
    let data = [1u8, 2, 3, 4];
    let encoded = data.try_to_bech32("test").expect("encode");
    assert!(Fixed::<[u8; 4]>::try_from_bech32(&encoded, "other").is_err());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_unchecked_roundtrip() {
    use secure_gate::ToBech32;
    let data = [5u8, 6, 7, 8];
    let encoded = data.try_to_bech32("myhrp").expect("encode");
    let decoded = Fixed::<[u8; 4]>::try_from_bech32_unchecked(&encoded).expect("decode");
    decoded.with_secret(|b| assert_eq!(b, &[5u8, 6, 7, 8]));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_wrong_length_fails() {
    use secure_gate::ToBech32;
    // Encode 5 bytes but try to decode as 4-byte Fixed
    let data = [1u8, 2, 3, 4, 5];
    let encoded = data.try_to_bech32("test").expect("encode");
    assert!(Fixed::<[u8; 4]>::try_from_bech32(&encoded, "test").is_err());
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_roundtrip() {
    use secure_gate::ToBech32m;
    let data = [0xAAu8, 0xBB, 0xCC, 0xDD];
    let encoded = data.try_to_bech32m("key").expect("encode");
    let decoded = Fixed::<[u8; 4]>::try_from_bech32m(&encoded, "key").expect("decode");
    decoded.with_secret(|b| assert_eq!(b, &[0xAAu8, 0xBB, 0xCC, 0xDD]));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_hrp_mismatch_fails() {
    use secure_gate::ToBech32m;
    let data = [1u8, 2, 3, 4];
    let encoded = data.try_to_bech32m("key").expect("encode");
    assert!(Fixed::<[u8; 4]>::try_from_bech32m(&encoded, "other").is_err());
}

// --- Additional no-alloc Bech32 decode path tests ---

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_single_byte() {
    use secure_gate::ToBech32;
    let data = [0xABu8];
    let encoded = data.try_to_bech32("t").expect("encode");
    let decoded = Fixed::<[u8; 1]>::try_from_bech32(&encoded, "t").expect("decode");
    decoded.with_secret(|b| assert_eq!(b, &[0xABu8]));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_hrp_case_insensitive() {
    use secure_gate::ToBech32;
    let data = [1u8, 2, 3, 4];
    // bech32 encoding lowercases the HRP; decoding should accept any case
    let encoded = data.try_to_bech32("test").expect("encode");
    let decoded = Fixed::<[u8; 4]>::try_from_bech32(&encoded, "TEST").expect("case-insensitive");
    decoded.with_secret(|b| assert_eq!(b, &[1u8, 2, 3, 4]));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_invalid_checksum() {
    use secure_gate::ToBech32;
    let data = [1u8, 2, 3, 4];
    let mut encoded = data.try_to_bech32("test").expect("encode");
    // Flip the last character to corrupt the checksum
    let len = encoded.len();
    let last = encoded.as_bytes()[len - 1];
    let flipped = if last == b'q' { b'p' } else { b'q' };
    unsafe { encoded.as_bytes_mut()[len - 1] = flipped; }
    assert!(Fixed::<[u8; 4]>::try_from_bech32(&encoded, "test").is_err());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_too_short() {
    use secure_gate::ToBech32;
    // Encode 2 bytes, try to decode as 4-byte Fixed
    let data = [1u8, 2];
    let encoded = data.try_to_bech32("test").expect("encode");
    assert!(Fixed::<[u8; 4]>::try_from_bech32(&encoded, "test").is_err());
}

#[cfg(all(feature = "encoding-bech32", feature = "encoding-bech32m"))]
#[test]
fn fixed_try_from_bech32_rejects_bech32m_checksum() {
    use secure_gate::ToBech32m;
    // Encode with bech32m checksum, try to decode as bech32 (standard) — should fail
    let data = [1u8, 2, 3, 4];
    let encoded = data.try_to_bech32m("test").expect("bech32m encode");
    assert!(Fixed::<[u8; 4]>::try_from_bech32(&encoded, "test").is_err());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_try_from_bech32_unchecked_wrong_length() {
    use secure_gate::ToBech32;
    let data = [1u8, 2, 3, 4, 5];
    let encoded = data.try_to_bech32("test").expect("encode");
    assert!(Fixed::<[u8; 4]>::try_from_bech32_unchecked(&encoded).is_err());
}

// --- Additional no-alloc Bech32m decode path tests ---

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_single_byte() {
    use secure_gate::ToBech32m;
    let data = [0xCDu8];
    let encoded = data.try_to_bech32m("t").expect("encode");
    let decoded = Fixed::<[u8; 1]>::try_from_bech32m(&encoded, "t").expect("decode");
    decoded.with_secret(|b| assert_eq!(b, &[0xCDu8]));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_hrp_case_insensitive() {
    use secure_gate::ToBech32m;
    let data = [1u8, 2, 3, 4];
    let encoded = data.try_to_bech32m("key").expect("encode");
    let decoded = Fixed::<[u8; 4]>::try_from_bech32m(&encoded, "KEY").expect("case-insensitive");
    decoded.with_secret(|b| assert_eq!(b, &[1u8, 2, 3, 4]));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_invalid_checksum() {
    use secure_gate::ToBech32m;
    let data = [1u8, 2, 3, 4];
    let mut encoded = data.try_to_bech32m("key").expect("encode");
    let len = encoded.len();
    let last = encoded.as_bytes()[len - 1];
    let flipped = if last == b'q' { b'p' } else { b'q' };
    unsafe { encoded.as_bytes_mut()[len - 1] = flipped; }
    assert!(Fixed::<[u8; 4]>::try_from_bech32m(&encoded, "key").is_err());
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_too_long() {
    use secure_gate::ToBech32m;
    let data = [1u8, 2, 3, 4, 5];
    let encoded = data.try_to_bech32m("key").expect("encode");
    assert!(Fixed::<[u8; 4]>::try_from_bech32m(&encoded, "key").is_err());
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_too_short() {
    use secure_gate::ToBech32m;
    let data = [1u8, 2];
    let encoded = data.try_to_bech32m("key").expect("encode");
    assert!(Fixed::<[u8; 4]>::try_from_bech32m(&encoded, "key").is_err());
}

#[cfg(all(feature = "encoding-bech32", feature = "encoding-bech32m"))]
#[test]
fn fixed_try_from_bech32m_rejects_bech32_checksum() {
    use secure_gate::ToBech32;
    // Encode with bech32 (standard) checksum, try to decode as bech32m — should fail
    let data = [1u8, 2, 3, 4];
    let encoded = data.try_to_bech32("test").expect("bech32 encode");
    assert!(Fixed::<[u8; 4]>::try_from_bech32m(&encoded, "test").is_err());
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_unchecked_roundtrip() {
    use secure_gate::ToBech32m;
    let data = [5u8, 6, 7, 8];
    let encoded = data.try_to_bech32m("myhrp").expect("encode");
    let decoded = Fixed::<[u8; 4]>::try_from_bech32m_unchecked(&encoded).expect("decode");
    decoded.with_secret(|b| assert_eq!(b, &[5u8, 6, 7, 8]));
}

#[cfg(feature = "encoding-bech32m")]
#[test]
fn fixed_try_from_bech32m_unchecked_wrong_length() {
    use secure_gate::ToBech32m;
    let data = [1u8, 2, 3, 4, 5];
    let encoded = data.try_to_bech32m("key").expect("encode");
    assert!(Fixed::<[u8; 4]>::try_from_bech32m_unchecked(&encoded).is_err());
}
