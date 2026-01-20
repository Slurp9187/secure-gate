//! Tests for error types defined in the `error.rs` module.

#[cfg(feature = "encoding-bech32")]
use secure_gate::Bech32EncodingError;

/// Test Bech32EncodingError variants (requires encoding-bech32 feature)
#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_encoding_error_variants() {
    let invalid_hrp = Bech32EncodingError::InvalidHrp;
    let encoding_failed = Bech32EncodingError::EncodingFailed;

    // Test that they are different variants
    assert_ne!(invalid_hrp, encoding_failed);
    assert_eq!(invalid_hrp, Bech32EncodingError::InvalidHrp);
    assert_eq!(encoding_failed, Bech32EncodingError::EncodingFailed);
}

/// Test Bech32EncodingError Clone, Copy, Debug, PartialEq, Eq
#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_encoding_error_traits() {
    let error1 = Bech32EncodingError::InvalidHrp;
    let error2 = error1; // Copy
    let error3 = error1; // Copy

    assert_eq!(error1, error2);
    assert_eq!(error1, error3);

    // Debug formatting
    assert!(format!("{:?}", error1).contains("InvalidHrp"));
    assert!(format!("{:?}", Bech32EncodingError::EncodingFailed).contains("EncodingFailed"));
}

/// Test Bech32EncodingError display messages
#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_encoding_error_display() {
    assert_eq!(
        format!("{}", Bech32EncodingError::InvalidHrp),
        "invalid Human-Readable Part (HRP)"
    );
    assert_eq!(
        format!("{}", Bech32EncodingError::EncodingFailed),
        "encoding operation failed"
    );
}
