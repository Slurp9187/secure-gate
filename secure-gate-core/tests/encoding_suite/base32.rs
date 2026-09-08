//! encoding_suite/base32.rs — base32 encoding/decoding tests

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
use secure_gate::{fixed_newtype, Dynamic};
#[cfg(feature = "encoding-base32")]
use secure_gate::{Fixed, FromBase32Str, RevealSecret, ToBase32};

#[cfg(feature = "encoding-base32")]
#[test]
fn test_slice_to_base32() {
    let input = b"hello";
    let encoded = input.to_base32().into_inner();
    let decoded = encoded.try_from_base32().expect("valid base32");
    assert_eq!(decoded, b"hello");
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_roundtrip() {
    let fixed = Fixed::new([7u8; 32]);
    let encoded = fixed.to_base32().into_inner();
    let decoded = Fixed::<[u8; 32]>::try_from_base32(&encoded).expect("valid");
    decoded.with_secret(|d| assert_eq!(d, &[7u8; 32]));
}

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
#[test]
fn dynamic_try_from_base32_roundtrip() {
    let dynv: Dynamic<Vec<u8>> = vec![10, 20, 30].into();
    let encoded = dynv.to_base32().into_inner();
    let decoded = Dynamic::<Vec<u8>>::try_from_base32(&encoded).expect("valid");
    decoded.with_secret(|d| assert_eq!(d, &[10, 20, 30]));
}

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
#[test]
fn dynamic_try_from_base32_invalid_input_returns_err() {
    assert!(Dynamic::<Vec<u8>>::try_from_base32("not valid base32!!!").is_err());
}

// No-alloc decode path tests: Fixed::try_from_base32 works with only encoding-base32 (no alloc feature)
#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_wrong_length_too_long() {
    // "NBSWY3DP" decodes to 5 bytes — too long for [u8; 4]
    assert!(Fixed::<[u8; 4]>::try_from_base32("NBSWY3DP").is_err());
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_wrong_length_too_short() {
    // "MZXQ" decodes to 2 bytes — too short for [u8; 4]
    assert!(Fixed::<[u8; 4]>::try_from_base32("MZXQ").is_err());
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_invalid_chars() {
    // '!' is outside every alphabet; '0', '1', '8' and '9' are the digits RFC 4648 §6
    // deliberately omits (only '2'..='7' are used). N matches the length a well-formed
    // 4-character group decodes to, so a length mismatch cannot mask the alphabet check.
    assert!(Fixed::<[u8; 2]>::try_from_base32("!!!!").is_err());
    assert!(Fixed::<[u8; 2]>::try_from_base32("0189").is_err());
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_all_zeros() {
    // [0u8; 3] encodes as "AAAAA" in base32
    let result = Fixed::<[u8; 3]>::try_from_base32("AAAAA");
    assert!(result.is_ok());
    result.unwrap().with_secret(|b| assert_eq!(b, &[0u8; 3]));
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_empty_input() {
    assert!(Fixed::<[u8; 4]>::try_from_base32("").is_err());
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_zero_size() {
    // The empty string is the canonical encoding of zero bytes.
    let result = Fixed::<[u8; 0]>::try_from_base32("");
    assert!(result.is_ok());
    result.unwrap().with_secret(|b| assert_eq!(b, &[0u8; 0]));
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_single_byte() {
    // [0x00] encodes as "AA" in base32 (unpadded)
    let result = Fixed::<[u8; 1]>::try_from_base32("AA");
    assert!(result.is_ok());
    result.unwrap().with_secret(|b| assert_eq!(b, &[0u8]));
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_rejects_lowercase() {
    // base32ct 0.3 has no mixed-case decoder: the canonical form is uppercase only.
    // Both strings would decode to 5 bytes if case were folded, so N = 5 leaves the
    // case check as the only possible reason to fail.
    assert!(Fixed::<[u8; 5]>::try_from_base32("nbswy3dp").is_err());
    assert!(Fixed::<[u8; 5]>::try_from_base32("NbSwY3Dp").is_err());
    // The uppercase form of the same input is accepted, so the rejection is about case.
    assert!(Fixed::<[u8; 5]>::try_from_base32("NBSWY3DP").is_ok());
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_rejects_padding() {
    // The canonical form is unpadded; '=' is not in the alphabet. Each N is the length
    // the padding-stripped string decodes to, so padding is the only reason to fail.
    assert!(Fixed::<[u8; 1]>::try_from_base32("MY======").is_err());
    assert!(Fixed::<[u8; 2]>::try_from_base32("MZXQ====").is_err());
    assert!(Fixed::<[u8; 1]>::try_from_base32("MY").is_ok());
    assert!(Fixed::<[u8; 2]>::try_from_base32("MZXQ").is_ok());
    // Bare padding is not a zero-length encoding of nothing.
    assert!(Fixed::<[u8; 0]>::try_from_base32("=").is_err());
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_rejects_non_ascii() {
    // A multi-byte char is outside the alphabet and must not be sliced into bytes.
    assert!(Fixed::<[u8; 5]>::try_from_base32("NBSWY3DPé").is_err());
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_rejects_impossible_lengths() {
    // Lengths of 1, 3 and 6 (mod 8) cannot be produced by the encoder. Each N below is
    // the byte count the string *would* yield if the length rule were not enforced
    // (1 char → 0 bytes, 3 chars → 1 byte, 6 chars → 3 bytes), so these fail on the
    // length rule alone and not on a decoded-length mismatch.
    assert!(Fixed::<[u8; 0]>::try_from_base32("M").is_err());
    assert!(Fixed::<[u8; 1]>::try_from_base32("MZX").is_err());
    assert!(Fixed::<[u8; 3]>::try_from_base32("MZXW6Y").is_err());
    // The neighbouring legal lengths (2, 4, 5, 7, 8 mod 8) are accepted.
    assert!(Fixed::<[u8; 1]>::try_from_base32("MY").is_ok());
    assert!(Fixed::<[u8; 3]>::try_from_base32("MZXW6").is_ok());
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_rejects_whitespace() {
    // Whitespace is not skipped: "NBSW Y3DP" would be "NBSWY3DP" → 5 bytes if it were.
    assert!(Fixed::<[u8; 5]>::try_from_base32("NBSW Y3DP").is_err());
    assert!(Fixed::<[u8; 5]>::try_from_base32(" NBSWY3DP").is_err());
    assert!(Fixed::<[u8; 5]>::try_from_base32("NBSWY3DP\n").is_err());
}

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
#[test]
fn base32_rfc4648_section_10_vectors() {
    // RFC 4648 §10 base32 test vectors with the '=' padding stripped, which is this
    // crate's canonical form. Checked in both directions.
    const VECTORS: [(&[u8], &str); 6] = [
        (b"f", "MY"),
        (b"fo", "MZXQ"),
        (b"foo", "MZXW6"),
        (b"foob", "MZXW6YQ"),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI"),
    ];

    for (bytes, encoded) in VECTORS {
        let secret: Dynamic<Vec<u8>> = bytes.to_vec().into();
        assert_eq!(
            secret.to_base32().into_inner(),
            encoded,
            "encoding {bytes:?}"
        );

        let decoded = Dynamic::<Vec<u8>>::try_from_base32(encoded)
            .unwrap_or_else(|e| panic!("decoding {encoded}: {e}"));
        decoded.with_secret(|d| assert_eq!(d.as_slice(), bytes, "decoding {encoded}"));
    }
}

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
#[test]
fn base32_accepts_non_canonical_trailing_bits() {
    // Design decision D5: the backend ignores non-zero bits in the final partial group
    // rather than rejecting them, so "MZ" decodes like the canonical "MY". Documented,
    // deliberately not fixed — round-trip properties must therefore start from
    // encoder-produced strings, never from arbitrary valid-looking ones.
    assert_eq!("MY".try_from_base32().expect("canonical"), vec![0x66]);
    assert_eq!("MZ".try_from_base32().expect("non-canonical"), vec![0x66]);
    // Re-encoding normalises back to the canonical spelling.
    assert_eq!(
        "MZ".try_from_base32()
            .expect("non-canonical")
            .to_base32()
            .into_inner(),
        "MY"
    );
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_totp_seed_size() {
    // A 20-byte TOTP/HOTP shared secret is 32 base32 characters — the `otpauth://` form,
    // and 8 characters shorter than the same seed in hex.
    let seed = Fixed::new([0xAAu8; 20]);
    let encoded = seed.to_base32().into_inner();
    assert_eq!(encoded.len(), 32);
    // Canonical output: uppercase letters and '2'..='7' only, no '=' padding.
    assert!(encoded
        .bytes()
        .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)));

    let decoded = Fixed::<[u8; 20]>::try_from_base32(&encoded).expect("valid");
    decoded.with_secret(|d| assert_eq!(d, &[0xAAu8; 20]));
}

#[cfg(feature = "encoding-base32")]
#[test]
fn fixed_try_from_base32_large_n() {
    let data = [0x42u8; 128];
    let encoded = data.to_base32().into_inner();
    let result = Fixed::<[u8; 128]>::try_from_base32(&encoded);
    assert!(result.is_ok());
    result
        .unwrap()
        .with_secret(|b| assert_eq!(b, &[0x42u8; 128]));
}

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
fixed_newtype!(pub B32Key, 4);

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
#[test]
fn to_base32_is_generic_over_wrappers() {
    // `ToBase32` is a trait, not a set of inherent methods: one bound has to accept the
    // wrappers, a generated newtype and a plain byte slice alike. A regression back to
    // inherent methods would fail to compile here rather than fail an assertion.
    fn export<S: ToBase32>(s: &S) -> String {
        s.to_base32().into_inner()
    }

    let fixed = Fixed::new([0xABu8; 4]);
    let dynv: Dynamic<Vec<u8>> = vec![0xABu8; 4].into();
    let newtype = B32Key::new([0xABu8; 4]);

    assert_eq!(export(&fixed), "VOV2XKY");
    assert_eq!(export(&dynv), "VOV2XKY");
    assert_eq!(export(&newtype), "VOV2XKY");
    assert_eq!(export(&[0xABu8; 4]), "VOV2XKY");

    // The same bound also hands the wrapper back unopened, which is what a caller
    // does when it never needs an owned `String`.
    fn export_wrapped<S: ToBase32>(s: &S) -> secure_gate::EncodedSecret {
        s.to_base32()
    }
    assert_eq!(&*export_wrapped(&newtype), "VOV2XKY");
}

/// Regression guard specific to the 0.8 line.
///
/// `base32ct` 0.2 (the newest release that builds on MSRV 1.70) sizes its output
/// buffer from `decoded_len()` but indexes it from the input remainder, so an
/// encoded length whose trailing block is 1, 3 or 6 characters writes out of
/// bounds and panics instead of returning an error. `secure-gate` guards every
/// delegation to `base32ct`, so these must be ordinary `Err`s — a panic here
/// would be a denial-of-service path on attacker-supplied input.
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
#[test]
fn base32_impossible_block_lengths_error_and_never_panic() {
    use secure_gate::{Dynamic, Fixed};

    // Trailing blocks of 1, 3 and 6 chars are unrepresentable in unpadded Base32.
    for len in [1usize, 3, 6, 9, 11, 14, 17, 19, 22] {
        assert!(
            !matches!(len % 8, 0 | 2 | 4 | 5 | 7),
            "test vector {len} must be an impossible length"
        );
        let s = "A".repeat(len);
        assert!(
            Fixed::<[u8; 4]>::try_from_base32(&s).is_err(),
            "Fixed must reject impossible length {len} without panicking"
        );
        assert!(
            Dynamic::<Vec<u8>>::try_from_base32(&s).is_err(),
            "Dynamic must reject impossible length {len} without panicking"
        );
    }

    // The valid trailing blocks must still decode (or fail on length, not shape).
    for len in [2usize, 4, 5, 7, 8] {
        let s = "A".repeat(len);
        let _ = Dynamic::<Vec<u8>>::try_from_base32(&s);
    }
}
