//! encoding_suite/bech32_sized.rs — caller-chosen bech32 / bech32m code lengths.
//!
//! The invariants under test, stated once:
//!
//! 1. `N` is a **length gate only** — it never enters the checksum, so the same bytes
//!    and HRP encode byte-identically at every `N` that admits them.
//! 2. A string decodes under any `N` at least as large as the string itself, and under
//!    no `N` smaller.
//! 3. Bech32 and Bech32m are **different checksums, not different size classes** — no
//!    code length makes one decode as the other.
//! 4. Everything the default methods guarantee (HRP validation, exact length reporting,
//!    zeroizing output, BIP test vectors) holds identically on the `_sized` path.

#![cfg(all(feature = "encoding-bech32", feature = "alloc"))]

use secure_gate::{BECH32_CODE_LENGTH, Bech32Error, bech32_code_length};

#[cfg(feature = "encoding-bech32")]
use secure_gate::{FromBech32Str, ToBech32};
#[cfg(feature = "encoding-bech32")]
use secure_gate::{FromBech32mStr, ToBech32m};
#[cfg(feature = "encoding-bech32")]
use secure_gate::{Dynamic, Fixed, RevealSecret};

// ─────────────────────────── the helper ───────────────────────────

#[test]
fn code_length_helper_matches_the_real_encoded_length() {
    // hrp + '1' + ceil(bytes*8/5) + 6
    assert_eq!(bech32_code_length(0, 0), 7);
    assert_eq!(bech32_code_length(3, 0), 10);
    assert_eq!(bech32_code_length(1, 1), 10); // ceil(8/5) = 2
    assert_eq!(bech32_code_length(3, 32), 62); // ceil(256/5) = 52
    assert_eq!(BECH32_CODE_LENGTH, 1023);
}

/// The helper is total: it never panics and never wraps to a too-small value.
/// Adversarial review found the original `payload_bytes * 8` panicked in debug and
/// wrapped in release for payloads above `usize::MAX / 8`.
#[test]
fn code_length_saturates_instead_of_wrapping() {
    // Results that cannot fit in a usize saturate to usize::MAX, which every encoder
    // then refuses — never a small, wrong number that would under-size a buffer.
    assert_eq!(bech32_code_length(3, usize::MAX), usize::MAX);
    assert_eq!(bech32_code_length(usize::MAX, 0), usize::MAX);
    assert_eq!(bech32_code_length(usize::MAX, usize::MAX), usize::MAX);
    // Just past the old overflow point the true answer still fits, and is returned
    // exactly rather than wrapped: 8·(b/5) + ceil(8·(b%5)/5) + 10.
    let b = usize::MAX / 8 + 1;
    let expected = (b / 5) * 8 + ((b % 5) * 8).div_ceil(5) + 10;
    assert_eq!(bech32_code_length(3, b), expected);
    assert!(expected > usize::MAX / 8, "sanity: the exact answer is large, not wrapped");
    // Ordinary inputs are unaffected.
    assert_eq!(bech32_code_length(3, 32), 62);
    assert_eq!(bech32_code_length(3, 633), 1023);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn helper_is_exact_not_approximate() {
    // For each case the computed N must be the *smallest* value that works: the
    // encoding is exactly N characters long, and N-1 is rejected.
    macro_rules! exact {
        ($hrp:literal, $len:expr) => {{
            const N: usize = bech32_code_length($hrp.len(), $len);
            let data = vec![0x5Au8; $len];
            let encoded = data
                .try_to_bech32_sized::<N>($hrp)
                .expect("the computed code length must fit");
            assert_eq!(
                encoded.len(),
                N,
                "computed N is not the encoded length for hrp={} len={}",
                $hrp,
                $len
            );
            assert_eq!(
                data.try_to_bech32_sized::<{ N - 1 }>($hrp),
                Err(Bech32Error::OperationFailed),
                "N-1 must be too small for hrp={} len={}",
                $hrp,
                $len
            );
        }};
    }

    exact!("a", 0);
    exact!("a", 1);
    exact!("age", 32);
    exact!("x", 977);
    exact!("kem", 1568);
    exact!("verylonghrpstring", 64);
}

// ─────────────────── invariant 1: N never enters the checksum ───────────────────

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_output_is_byte_identical_across_code_lengths() {
    let data = [0xABu8; 32];
    let a = data.try_to_bech32_sized::<62>("age").expect("exact fit");
    let b = data.try_to_bech32_sized::<1023>("age").expect("default");
    let c = data.try_to_bech32_sized::<65535>("age").expect("huge");
    let d = data.try_to_bech32("age").expect("plain method");
    assert_eq!(a, b);
    assert_eq!(b, c);
    assert_eq!(c, d, "the plain method must equal the default code length");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32m_output_is_byte_identical_across_code_lengths() {
    let data = [0xABu8; 32];
    let a = data.try_to_bech32m_sized::<62>("age").expect("exact fit");
    let b = data.try_to_bech32m_sized::<1023>("age").expect("default");
    let c = data.try_to_bech32m_sized::<65535>("age").expect("huge");
    let d = data.try_to_bech32m("age").expect("plain method");
    assert_eq!(a, b);
    assert_eq!(b, c);
    assert_eq!(c, d);
}

// ─────────────────── invariant 2: N bounds length, both directions ───────────────────

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_short_string_written_large_decodes_at_the_default() {
    let data = [0x11u8; 32];
    let encoded = data.try_to_bech32_sized::<65535>("age").expect("encodes");
    assert!(encoded.len() < BECH32_CODE_LENGTH);
    // Written at 65535, read at 1023: fine, because the string itself is short.
    assert_eq!(encoded.try_from_bech32("age").expect("decodes"), data);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_long_string_needs_a_large_n_at_both_ends() {
    let data = vec![0x22u8; 900]; // 1440 payload chars
    assert_eq!(data.try_to_bech32("age"), Err(Bech32Error::OperationFailed));

    let encoded = data.try_to_bech32_sized::<2519>("age").expect("2519 fits");
    assert!(encoded.len() > BECH32_CODE_LENGTH);

    assert_eq!(
        encoded.try_from_bech32("age"),
        Err(Bech32Error::OperationFailed),
        "the default code length must refuse an over-long string"
    );
    assert_eq!(
        encoded.try_from_bech32_sized::<2519>("age").expect("round trip"),
        data
    );
    // Any larger N also works.
    assert_eq!(
        encoded.try_from_bech32_sized::<65535>("age").expect("larger N"),
        data
    );
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32m_long_string_needs_a_large_n_at_both_ends() {
    let data = vec![0x22u8; 900];
    assert_eq!(data.try_to_bech32m("age"), Err(Bech32Error::OperationFailed));

    let encoded = data.try_to_bech32m_sized::<2519>("age").expect("2519 fits");
    assert_eq!(
        encoded.try_from_bech32m("age"),
        Err(Bech32Error::OperationFailed)
    );
    assert_eq!(
        encoded
            .try_from_bech32m_sized::<2519>("age")
            .expect("round trip"),
        data
    );
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn boundary_exactly_at_and_one_past_the_code_length() {
    // Largest payload whose encoding is exactly BECH32_CODE_LENGTH characters,
    // for a 3-character HRP: (1023 - 3 - 1 - 6) * 5 / 8 = 633 bytes.
    let fits = vec![0x33u8; 633];
    let encoded = fits.try_to_bech32("age").expect("633 bytes must fit");
    assert_eq!(encoded.len(), BECH32_CODE_LENGTH);
    assert_eq!(encoded.try_from_bech32("age").expect("decodes"), fits);

    // One byte more must not.
    let over = vec![0x33u8; 634];
    assert_eq!(over.try_to_bech32("age"), Err(Bech32Error::OperationFailed));
}

// ─────────────────── invariant 3: the two checksums never cross ───────────────────

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_and_bech32m_never_cross_decode_at_any_code_length() {
    let data = [0x44u8; 32];

    let b32 = data.try_to_bech32("x").expect("bech32");
    let b32m = data.try_to_bech32m("x").expect("bech32m");
    assert_ne!(b32, b32m, "different residues must give different strings");

    // Short strings, well inside every code length: still mutually undecodable.
    assert_eq!(b32.try_from_bech32m("x"), Err(Bech32Error::OperationFailed));
    assert_eq!(b32m.try_from_bech32("x"), Err(Bech32Error::OperationFailed));

    // And a generous code length does not rescue either direction.
    assert_eq!(
        b32.try_from_bech32m_sized::<65535>("x"),
        Err(Bech32Error::OperationFailed)
    );
    assert_eq!(
        b32m.try_from_bech32_sized::<65535>("x"),
        Err(Bech32Error::OperationFailed)
    );
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn long_payloads_also_never_cross_decode() {
    let data = vec![0x55u8; 900];
    let b32 = data.try_to_bech32_sized::<2519>("x").expect("bech32");
    let b32m = data.try_to_bech32m_sized::<2519>("x").expect("bech32m");
    assert_ne!(b32, b32m);
    assert_eq!(
        b32.try_from_bech32m_sized::<2519>("x"),
        Err(Bech32Error::OperationFailed)
    );
    assert_eq!(
        b32m.try_from_bech32_sized::<2519>("x"),
        Err(Bech32Error::OperationFailed)
    );
}

// ─────────────────── invariant 4: the guarantees carry over ───────────────────

#[cfg(feature = "encoding-bech32")]
#[test]
fn sized_still_validates_the_hrp() {
    let data = vec![0x66u8; 900];
    let encoded = data.try_to_bech32_sized::<2519>("age").expect("encodes");
    assert_eq!(
        encoded.try_from_bech32_sized::<2519>("kem"),
        Err(Bech32Error::UnexpectedHrp)
    );
    // Case-insensitive, as on the default path.
    assert_eq!(
        encoded
            .try_from_bech32_sized::<2519>("AGE")
            .expect("case-insensitive"),
        data
    );
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn sized_unchecked_returns_the_hrp_without_validating_it() {
    let data = vec![0x77u8; 900];
    let encoded = data.try_to_bech32_sized::<2519>("age").expect("encodes");
    let (hrp, bytes) = encoded
        .try_from_bech32_unchecked_sized::<2519>()
        .expect("decodes");
    assert_eq!(hrp.to_ascii_lowercase(), "age");
    assert_eq!(bytes, data);
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn sized_zeroizing_variant_returns_an_encoded_secret() {
    let data = vec![0x88u8; 900];
    let enc = data
        .try_to_bech32_sized_zeroizing::<2519>("age")
        .expect("encodes");
    assert!(enc.starts_with("age1"));
    // Redacted Debug, like every EncodedSecret.
    assert_eq!(format!("{enc:?}"), "[REDACTED]");
    let plain = data.try_to_bech32_sized::<2519>("age").expect("encodes");
    assert_eq!(&*enc, plain.as_str());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn sized_zeroizing_variant_bech32m() {
    let data = vec![0x99u8; 900];
    let enc = data
        .try_to_bech32m_sized_zeroizing::<2519>("age")
        .expect("encodes");
    assert!(enc.starts_with("age1"));
    assert_eq!(format!("{enc:?}"), "[REDACTED]");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bip173_test_vectors_still_pass_on_both_paths() {
    // The minimal BIP-173 vector, through the default and through a sized call.
    let data = "A12UEL5L".try_from_bech32("A").expect("BIP-173 vector");
    assert!(data.is_empty());
    let data = "A12UEL5L"
        .try_from_bech32_sized::<1023>("A")
        .expect("same vector, sized");
    assert!(data.is_empty());
    let data = "A12UEL5L"
        .try_from_bech32_sized::<65535>("A")
        .expect("same vector, huge N");
    assert!(data.is_empty());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bip350_test_vectors_still_pass_on_both_paths() {
    let data = "A1LQFN3A".try_from_bech32m("A").expect("BIP-350 vector");
    assert!(data.is_empty());
    let data = "A1LQFN3A"
        .try_from_bech32m_sized::<65535>("A")
        .expect("same vector, huge N");
    assert!(data.is_empty());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn empty_payload_round_trips_at_every_code_length() {
    let empty: [u8; 0] = [];
    // (`try_to_bech32_sized` is on the byte slice, so annotate the array explicitly.)
    for encoded in [
        empty.try_to_bech32_sized::<10>("a").expect("minimum"),
        empty.try_to_bech32_sized::<1023>("a").expect("default"),
        empty.try_to_bech32_sized::<65535>("a").expect("huge"),
    ] {
        let decoded: Vec<u8> = encoded.try_from_bech32("a").expect("decodes");
        assert!(decoded.is_empty());
    }
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn a_code_length_too_small_for_the_payload_is_an_error_not_a_truncation() {
    let data = [0xAAu8; 32]; // needs 62 characters with a 3-char HRP
    assert_eq!(
        data.try_to_bech32_sized::<61>("age"),
        Err(Bech32Error::OperationFailed)
    );
    assert!(data.try_to_bech32_sized::<62>("age").is_ok());
}

// ─────────────────── wrapper types ───────────────────

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_sized_round_trip_and_length_mismatch() {
    let secret = Fixed::new([0xBBu8; 32]);
    let encoded = secret
        .try_to_bech32_sized::<2519>("age")
        .expect("wrapper encodes");
    let back = Fixed::<[u8; 32]>::try_from_bech32_sized::<2519>(&encoded, "age")
        .expect("wrapper decodes");
    back.with_secret(|b| assert_eq!(b, &[0xBBu8; 32]));

    // Wrong target length reports the exact decoded count.
    let err = Fixed::<[u8; 16]>::try_from_bech32_sized::<2519>(&encoded, "age")
        .expect_err("length mismatch must fail");
    assert!(
        matches!(
            err,
            Bech32Error::InvalidLength {
                expected: 16,
                got: 32,
                ..
            }
        ),
        "expected an exact InvalidLength, got {err:?}"
    );
    // HRP is still validated.
    assert_eq!(
        Fixed::<[u8; 32]>::try_from_bech32_sized::<2519>(&encoded, "kem")
            .expect_err("hrp mismatch must fail"),
        Bech32Error::UnexpectedHrp
    );
    // Unchecked variant ignores the HRP but keeps the length check.
    Fixed::<[u8; 32]>::try_from_bech32_unchecked_sized::<2519>(&encoded)
        .expect("unchecked decodes")
        .with_secret(|b| assert_eq!(b, &[0xBBu8; 32]));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn fixed_sized_round_trip_bech32m() {
    let secret = Fixed::new([0xCCu8; 32]);
    let encoded = secret
        .try_to_bech32m_sized::<2519>("age")
        .expect("wrapper encodes");
    Fixed::<[u8; 32]>::try_from_bech32m_sized::<2519>(&encoded, "age")
        .expect("wrapper decodes")
        .with_secret(|b| assert_eq!(b, &[0xCCu8; 32]));
    assert_eq!(
        Fixed::<[u8; 32]>::try_from_bech32m_sized::<2519>(&encoded, "kem")
            .expect_err("hrp mismatch must fail"),
        Bech32Error::UnexpectedHrp
    );
    Fixed::<[u8; 32]>::try_from_bech32m_unchecked_sized::<2519>(&encoded)
        .expect("unchecked decodes")
        .with_secret(|b| assert_eq!(b, &[0xCCu8; 32]));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn dynamic_sized_round_trip_for_a_kem_sized_payload() {
    // ML-KEM-1024 ciphertext: 1568 bytes, far past the default code length.
    let ct = vec![0x5Au8; 1568];
    let secret = Dynamic::new(ct.clone());

    assert_eq!(
        secret.try_to_bech32("kem"),
        Err(Bech32Error::OperationFailed),
        "the default must refuse a KEM ciphertext"
    );

    const N: usize = bech32_code_length(3, 1568);
    let encoded = secret.try_to_bech32_sized::<N>("kem").expect("encodes");
    assert_eq!(encoded.len(), N);

    let back = Dynamic::<Vec<u8>>::try_from_bech32_sized::<N>(&encoded, "kem").expect("decodes");
    back.with_secret(|b| assert_eq!(b, &ct));

    assert_eq!(
        Dynamic::<Vec<u8>>::try_from_bech32_sized::<N>(&encoded, "age")
            .expect_err("hrp mismatch must fail"),
        Bech32Error::UnexpectedHrp
    );
    Dynamic::<Vec<u8>>::try_from_bech32_unchecked_sized::<N>(&encoded)
        .expect("unchecked decodes")
        .with_secret(|b| assert_eq!(b, &ct));
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn dynamic_sized_round_trip_bech32m() {
    let ct = vec![0x6Bu8; 1568];
    let secret = Dynamic::new(ct.clone());
    const N: usize = bech32_code_length(3, 1568);
    let encoded = secret.try_to_bech32m_sized::<N>("kem").expect("encodes");
    Dynamic::<Vec<u8>>::try_from_bech32m_sized::<N>(&encoded, "kem")
        .expect("decodes")
        .with_secret(|b| assert_eq!(b, &ct));
    Dynamic::<Vec<u8>>::try_from_bech32m_unchecked_sized::<N>(&encoded)
        .expect("unchecked decodes")
        .with_secret(|b| assert_eq!(b, &ct));
}

// ─────────────────── an age-shaped end-to-end case ───────────────────

#[cfg(feature = "encoding-bech32")]
#[test]
fn age_style_recipient_list_round_trips() {
    // A batch of X25519 recipients: 40 * 32 bytes.
    let recipients: Vec<u8> = (0..40u8).flat_map(|i| [i; 32]).collect();
    assert_eq!(recipients.len(), 1280);

    const N: usize = bech32_code_length(3, 1280);
    let encoded = recipients
        .try_to_bech32_sized_zeroizing::<N>("age")
        .expect("encodes");
    assert!(encoded.starts_with("age1"));
    assert_eq!(format!("{encoded:?}"), "[REDACTED]");

    let decoded = encoded
        .try_from_bech32_sized::<N>("age")
        .expect("round trips");
    assert_eq!(decoded, recipients);
}

// ─────────────────── corruption is still detected ───────────────────

#[cfg(feature = "encoding-bech32")]
#[test]
fn single_character_corruption_is_rejected_at_large_code_lengths() {
    let data = vec![0x7Eu8; 900];
    let encoded = data.try_to_bech32_sized::<2519>("age").expect("encodes");

    // Flip one payload character to a different valid bech32 character.
    let mut bytes = encoded.clone().into_bytes();
    let idx = bytes.len() - 20;
    bytes[idx] = if bytes[idx] == b'q' { b'p' } else { b'q' };
    let corrupted = String::from_utf8(bytes).expect("still ascii");
    assert_ne!(corrupted, encoded);

    assert_eq!(
        corrupted.try_from_bech32_sized::<2519>("age"),
        Err(Bech32Error::OperationFailed),
        "a one-character corruption must not decode"
    );
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn truncated_and_extended_strings_are_rejected() {
    let data = vec![0x7Fu8; 900];
    let encoded = data.try_to_bech32_sized::<2519>("age").expect("encodes");

    let truncated = &encoded[..encoded.len() - 1];
    assert!(truncated.try_from_bech32_sized::<2519>("age").is_err());

    let extended = format!("{encoded}q");
    assert!(extended.try_from_bech32_sized::<2519>("age").is_err());
}

// ─────────────────── randomized stress over the whole ladder ───────────────────

/// A deterministic xorshift, so a failure reproduces exactly from the printed seed.
/// (libFuzzer covers this ground in CI; this keeps the same invariants under wide
/// input coverage on platforms where the fuzzer cannot link.)
#[cfg(feature = "encoding-bech32")]
struct Lcg(u64);

#[cfg(feature = "encoding-bech32")]
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() & 0xFF) as u8).collect()
    }
}

/// Every invariant at once, across a ladder of code lengths and many random payloads.
///
/// Each rung is defined by a payload byte count `B`; its code length is
/// `bech32_code_length(3, B)`, so the rung is *achievable* — a string of exactly that
/// length exists — and case 0 of every rung encodes exactly `B` bytes to produce it.
/// That is what makes invariant 3 (a decoder one character too small refuses) a real
/// assertion on every rung: the previous version of this test used power-of-two rungs,
/// and because `gcd(8, 5) = 1` a 3-character-HRP code length can only ever be
/// `≡ {1, 2, 4, 6, 7} (mod 8)`, so no string was ever exactly 64, 128, 256, 1024, 2048
/// or 4096 long and the boundary assertion was vacuous on six of seven rungs. Caught
/// by adversarial review; the counter at the end pins that it cannot regress.
#[cfg(feature = "encoding-bech32")]
#[test]
fn randomized_stress_across_code_lengths() {
    macro_rules! ladder {
        ($($b:literal),+ $(,)?) => {
            let mut rng = Lcg(0x5EC0_DE5E_C0DE_5EC0);
            let mut checked = 0usize;
            let mut boundary_hits = 0usize;
            let rungs = [$($b),+].len();
            $(
                {
                    const N: usize = bech32_code_length(3, $b);
                    for case in 0..64u32 {
                        // Case 0 lands exactly on the rung; the rest straddle it.
                        let len = if case == 0 { $b } else { (rng.next() as usize) % ($b + 16) };
                        let data = rng.bytes(len);
                        let seed_note = format!("N={} B={} case={} len={}", N, $b, case, len);

                        let encoded = match data.try_to_bech32_sized::<N>("age") {
                            Ok(e) => e,
                            Err(Bech32Error::OperationFailed) => {
                                // Only legitimate when the string would exceed N.
                                assert!(
                                    bech32_code_length(3, len) > N,
                                    "refused a payload that fits: {seed_note}"
                                );
                                continue;
                            }
                            Err(other) => panic!("unexpected encode error {other:?}: {seed_note}"),
                        };
                        checked += 1;

                        assert_eq!(encoded.len(), bech32_code_length(3, len), "{seed_note}");

                        // 1. Round-trips at its own code length.
                        assert_eq!(
                            encoded.try_from_bech32_sized::<N>("age").expect(&seed_note),
                            data,
                            "{seed_note}"
                        );

                        // 2. The encoding does not depend on N: a bigger N gives the same bytes.
                        assert_eq!(
                            data.try_to_bech32_sized::<65535>("age").expect(&seed_note),
                            encoded,
                            "code length changed the encoding: {seed_note}"
                        );

                        // 3. Exactly at the boundary, a decoder one character too small
                        //    refuses. Reached on every rung via case 0 (counted below).
                        if encoded.len() == N {
                            boundary_hits += 1;
                            assert_eq!(
                                encoded.try_from_bech32_sized::<{ N - 1 }>("age"),
                                Err(Bech32Error::OperationFailed),
                                "a decoder one short of the string accepted it: {seed_note}"
                            );
                        }

                        // 4. The HRP is still validated.
                        assert_eq!(
                            encoded.try_from_bech32_sized::<N>("kem"),
                            Err(Bech32Error::UnexpectedHrp),
                            "{seed_note}"
                        );

                        // 5. Bech32m never decodes a bech32 string, at any code length.
                        assert!(
                            encoded.try_from_bech32m_sized::<65535>("age").is_err(),
                            "bech32 string decoded as bech32m: {seed_note}"
                        );
                    }
                }
            )+
            assert!(checked > 200, "stress test exercised only {checked} encodings");
            assert!(
                boundary_hits >= rungs,
                "the exact-length boundary was exercised on only {boundary_hits} of {rungs} rungs"
            );
        };
    }

    // Payload byte counts; code lengths are 62, 113, 215, 1023, 1034, 2058, 4106.
    ladder!(32, 64, 128, 633, 640, 1280, 2560);
}

// ─────────────────── the encode buffer is allocated once, exactly ───────────────────

/// Encoding must not reallocate.
///
/// `bech32::encode_lower` starts from `String::new()` and grows; each intermediate
/// buffer holds a partial copy of the encoded secret and is freed unwiped, which
/// `Zeroizing` explicitly cannot reach ("cannot ensure that previous reallocations did
/// not leave values on the heap"). Before the fix, a 1568-byte payload produced a
/// string of len 2519 with capacity 4096 — proof that a copy had been left behind.
///
/// `capacity() == len()` is the observable signature of a single exact allocation.
#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_encode_allocates_exactly_once() {
    for len in [0usize, 1, 32, 128, 633, 634, 900, 1568, 4096] {
        let data = vec![0x5Au8; len];
        const BIG: usize = 65535;

        let encoded = data.try_to_bech32_sized::<BIG>("age").expect("encodes");
        assert_eq!(
            encoded.capacity(),
            encoded.len(),
            "bech32 encode reallocated for a {len}-byte payload: \
             len {} but capacity {} — an unwiped partial copy was left on the heap",
            encoded.len(),
            encoded.capacity()
        );
        assert_eq!(encoded.len(), bech32_code_length(3, len));
    }
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32m_encode_allocates_exactly_once() {
    for len in [0usize, 1, 32, 633, 1568, 4096] {
        let data = vec![0x6Bu8; len];
        const BIG: usize = 65535;

        let encoded = data.try_to_bech32m_sized::<BIG>("age").expect("encodes");
        assert_eq!(
            encoded.capacity(),
            encoded.len(),
            "bech32m encode reallocated for a {len}-byte payload"
        );
        assert_eq!(encoded.len(), bech32_code_length(3, len));
    }
}

/// The zeroizing path inherits the same property: `EncodedSecret` wraps the string the
/// encoder built, so if that string had been grown, the wrapper could not have wiped
/// what was already freed.
#[cfg(feature = "encoding-bech32")]
#[test]
fn zeroizing_encode_wraps_an_exactly_sized_buffer() {
    let data = vec![0x77u8; 1568];
    const N: usize = bech32_code_length(3, 1568);
    let enc = data
        .try_to_bech32_sized_zeroizing::<N>("age")
        .expect("encodes");
    assert_eq!(enc.len(), N);
    let plain = data.try_to_bech32_sized::<N>("age").expect("encodes");
    assert_eq!(plain.capacity(), plain.len());
    assert_eq!(&*enc, plain.as_str());
}
