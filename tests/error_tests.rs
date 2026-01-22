// secure-gate\tests\error_tests.rs
//! Tests for error types defined in the `error.rs` module.

#[cfg(feature = "encoding-bech32")]
use secure_gate::Bech32Error;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
use secure_gate::DecodingError;

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
fn bech32_error_traits() {
    let error1 = Bech32Error::InvalidHrp;
    let error2 = error1; // Copy
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
    let invalid_encoding = DecodingError::InvalidEncoding;

    // Check that InvalidEncoding is present
    match invalid_encoding {
        DecodingError::InvalidEncoding => (),
        _ => panic!("Expected InvalidEncoding"),
    }

    // Test Display
    assert!(format!("{}", invalid_encoding).contains("invalid encoding"));
}
