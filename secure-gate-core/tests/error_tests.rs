// secure-gate\tests\error_tests.rs
//! Tests for error types defined in the `error.rs` module.
//!
//! All error enums are `#[non_exhaustive]`, and the struct variants
//! (`InvalidLength { expected, got }`) are `#[non_exhaustive]` too — they cannot
//! be constructed outside the crate. Length-mismatch errors are therefore
//! obtained here through the real decode APIs, which also verifies that the
//! constructors report accurate metadata.
//!
//! Error shapes and `Display` output are identical in debug and release builds —
//! several tests below assert the exact messages to lock that in.

#[cfg(feature = "encoding-bech32")]
use secure_gate::Bech32Error;

/// FromSliceError carries expected/got lengths in every build profile.
#[test]
fn from_slice_error_invalid_length() {
    let err = secure_gate::Fixed::<[u8; 4]>::try_from([0u8; 2].as_slice())
        .expect_err("length mismatch must fail");
    match err {
        secure_gate::FromSliceError::InvalidLength { expected, got, .. } => {
            assert_eq!(expected, 4);
            assert_eq!(got, 2);
        }
        _ => panic!("expected InvalidLength"),
    }
    assert_eq!(
        format!("{}", err),
        "slice length mismatch: expected 4, got 2"
    );

    // Errors are Copy — usable after being passed by value.
    let copied = err;
    assert_eq!(copied, err);
}

/// Test Bech32Error variants (requires encoding-bech32 feature)
#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_error_variants() {
    let invalid_hrp = Bech32Error::InvalidHrp;
    let operation_failed = Bech32Error::OperationFailed;

    // Test that they are different variants
    assert_ne!(invalid_hrp, operation_failed);
    assert_eq!(invalid_hrp, Bech32Error::InvalidHrp);
    assert_eq!(operation_failed, Bech32Error::OperationFailed);
}

/// Test Bech32Error Clone, Copy, Debug, PartialEq, Eq
#[cfg(feature = "encoding-bech32")]
#[test]
#[allow(clippy::clone_on_copy)]
fn bech32_error_traits() {
    let error1 = Bech32Error::InvalidHrp;
    let error2 = error1.clone(); // Clone
    let error3 = error1; // Copy

    assert_eq!(error1, error2);
    assert_eq!(error1, error3);

    // Debug formatting
    assert!(format!("{:?}", error1).contains("InvalidHrp"));
    assert!(format!("{:?}", Bech32Error::OperationFailed).contains("OperationFailed"));
}

/// Test Bech32Error display messages
#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_error_display() {
    assert_eq!(
        format!("{}", Bech32Error::InvalidHrp),
        "invalid Human-Readable Part (HRP)"
    );
    assert_eq!(
        format!("{}", Bech32Error::OperationFailed),
        "bech32 operation failed"
    );
}

/// HexError::InvalidLength carries expected/got in every build profile.
#[cfg(feature = "encoding-hex")]
#[test]
fn hex_error_invalid_length() {
    // 4 decoded bytes into a 2-byte target.
    let err = secure_gate::Fixed::<[u8; 2]>::try_from_hex("deadbeef")
        .expect_err("length mismatch must fail");
    match err {
        secure_gate::HexError::InvalidLength { expected, got, .. } => {
            assert_eq!(expected, 2);
            assert_eq!(got, 4);
        }
        _ => panic!("expected InvalidLength"),
    }
    assert_eq!(
        format!("{}", err),
        "decoded length mismatch: expected 2, got 4"
    );
}

/// Base32Error::InvalidLength carries expected/got in every build profile.
#[cfg(feature = "encoding-base32")]
#[test]
fn base32_error_invalid_length() {
    // "32W353Y" decodes to 4 bytes; target is 2.
    let err = secure_gate::Fixed::<[u8; 2]>::try_from_base32("32W353Y")
        .expect_err("length mismatch must fail");
    match err {
        secure_gate::Base32Error::InvalidLength { expected, got, .. } => {
            assert_eq!(expected, 2);
            assert_eq!(got, 4);
        }
        _ => panic!("expected InvalidLength"),
    }
    assert_eq!(
        format!("{}", err),
        "decoded length mismatch: expected 2, got 4"
    );

    // Copy like its siblings — usable after being passed by value. `Copy` also
    // pins the heap-free shape: the variant carries only numeric metadata, so it
    // can never own an allocation derived from the rejected input.
    let copied = err;
    assert_eq!(copied, err);
}

/// Base64Error::InvalidLength carries expected/got in every build profile.
#[cfg(feature = "encoding-base64")]
#[test]
fn base64_error_invalid_length() {
    // "3q2-7w" decodes to 4 bytes; target is 2.
    let err = secure_gate::Fixed::<[u8; 2]>::try_from_base64url("3q2-7w")
        .expect_err("length mismatch must fail");
    match err {
        secure_gate::Base64Error::InvalidLength { expected, got, .. } => {
            assert_eq!(expected, 2);
            assert_eq!(got, 4);
        }
        _ => panic!("expected InvalidLength"),
    }
    assert_eq!(
        format!("{}", err),
        "decoded length mismatch: expected 2, got 4"
    );
}

/// Bech32Error::InvalidLength carries expected/got in every build profile.
#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_error_invalid_length() {
    // BIP-173 minimal vector: HRP "a", empty payload — target expects 4 bytes.
    let err = secure_gate::Fixed::<[u8; 4]>::try_from_bech32("A12UEL5L", "a")
        .expect_err("length mismatch must fail");
    match err {
        Bech32Error::InvalidLength { expected, got, .. } => {
            assert_eq!(expected, 4);
            assert_eq!(got, 0);
        }
        _ => panic!("expected InvalidLength"),
    }
    assert_eq!(
        format!("{}", err),
        "decoded length mismatch: expected 4, got 0"
    );
}

/// Oversized payloads report the exact decoded length, not a truncated count.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
#[test]
fn bech32_error_invalid_length_oversized_exact() {
    use secure_gate::ToBech32;
    let encoded = [0u8; 8]
        .as_slice()
        .try_to_bech32("test", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    let err = secure_gate::Fixed::<[u8; 4]>::try_from_bech32(&encoded, "test")
        .expect_err("length mismatch must fail");
    match err {
        Bech32Error::InvalidLength { expected, got, .. } => {
            assert_eq!(expected, 4);
            assert_eq!(got, 8);
        }
        _ => panic!("expected InvalidLength"),
    }
}

/// Bech32Error::UnexpectedHrp is fieldless in every build profile — no
/// input-derived HRP strings are captured.
#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_error_unexpected_hrp() {
    let err = secure_gate::Fixed::<[u8; 4]>::try_from_bech32("A12UEL5L", "bc")
        .expect_err("HRP mismatch must fail");
    assert_eq!(err, Bech32Error::UnexpectedHrp);
    assert_eq!(format!("{}", err), "unexpected HRP");
}

/// The fieldless `Display` strings, which are written out by hand in `src/error.rs`
/// rather than derived. The `InvalidLength` arms are covered by the per-format
/// `*_invalid_length` tests above, which assert the interpolated message exactly.
#[cfg(feature = "encoding-hex")]
#[test]
fn hex_error_display() {
    assert_eq!(
        format!("{}", secure_gate::HexError::InvalidHex),
        "invalid hex string"
    );
}

#[cfg(feature = "encoding-base32")]
#[test]
fn base32_error_display() {
    assert_eq!(
        format!("{}", secure_gate::Base32Error::InvalidBase32),
        "invalid base32 string"
    );
}

#[cfg(feature = "encoding-base64")]
#[test]
fn base64_error_display() {
    assert_eq!(
        format!("{}", secure_gate::Base64Error::InvalidBase64),
        "invalid base64 string"
    );
}

/// Every error type still implements `core::error::Error`, which was previously
/// supplied by `thiserror`'s derive and is now a hand-written impl.
#[test]
fn error_types_implement_error_trait() {
    fn assert_error<E: std::error::Error>(_: &E) {}

    // `InvalidLength` is `#[non_exhaustive]`, so it cannot be built with a struct
    // expression from outside the crate — obtain one the way a caller would.
    let from_slice = secure_gate::Fixed::<[u8; 4]>::try_from([0u8; 2].as_slice())
        .expect_err("length mismatch must fail");
    assert_error(&from_slice);
    #[cfg(feature = "encoding-hex")]
    assert_error(&secure_gate::HexError::InvalidHex);
    #[cfg(feature = "encoding-base32")]
    assert_error(&secure_gate::Base32Error::InvalidBase32);
    #[cfg(feature = "encoding-base64")]
    assert_error(&secure_gate::Base64Error::InvalidBase64);
    #[cfg(feature = "encoding-bech32")]
    assert_error(&Bech32Error::OperationFailed);
}
