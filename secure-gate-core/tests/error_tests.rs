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

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
use secure_gate::DecodingError;

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

/// Test DecodingError variants and behavior
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
#[test]
fn decoding_error_variants() {
    // Fieldless in every build profile — no hint text is ever captured.
    let invalid_encoding = DecodingError::InvalidEncoding;

    match invalid_encoding {
        DecodingError::InvalidEncoding => (),
        _ => panic!("Expected InvalidEncoding"),
    }

    // Test Display
    assert_eq!(format!("{}", invalid_encoding), "invalid encoding");
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
    let encoded = [0u8; 8].as_slice().try_to_bech32("test").unwrap();
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

/// Test the DecodingError source() chain — verifies the hand-written
/// std::error::Error impl returns the inner error for each feature-gated
/// variant. On the 0.8 LTS line the Error impl is gated behind the `std`
/// feature (no core::error::Error on MSRV 1.70), so these tests are too.
#[cfg(all(feature = "std", feature = "encoding-hex"))]
#[test]
fn decoding_error_source_hex() {
    use std::error::Error;
    let inner = secure_gate::HexError::InvalidHex;
    let outer = DecodingError::InvalidHex(inner);
    let source = outer
        .source()
        .expect("DecodingError::InvalidHex must have a source");
    assert!(source.to_string().contains("invalid hex"));
}

#[cfg(all(feature = "std", feature = "encoding-base64"))]
#[test]
fn decoding_error_source_base64() {
    use std::error::Error;
    let inner = secure_gate::Base64Error::InvalidBase64;
    let outer = DecodingError::InvalidBase64(inner);
    let source = outer
        .source()
        .expect("DecodingError::InvalidBase64 must have a source");
    assert!(source.to_string().contains("invalid base64"));
}

#[cfg(all(feature = "std", feature = "encoding-bech32"))]
#[test]
fn decoding_error_source_bech32() {
    use std::error::Error;
    let inner = Bech32Error::OperationFailed;
    let outer = DecodingError::InvalidBech32(inner);
    let source = outer
        .source()
        .expect("DecodingError::InvalidBech32 must have a source");
    assert!(source.to_string().contains("bech32 operation failed"));
}
