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
#[allow(clippy::redundant_clone)]
fn bech32_error_traits() {
    let error1 = Bech32Error::InvalidHrp;
    let error2 = error1.clone(); // Clone
    let error3 = error1.clone(); // Clone

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
    #[cfg(debug_assertions)]
    let invalid_encoding = DecodingError::InvalidEncoding {
        hint: "test hint".to_string(),
    };
    #[cfg(not(debug_assertions))]
    let invalid_encoding = DecodingError::InvalidEncoding;

    // Check that InvalidEncoding is present
    #[cfg(debug_assertions)]
    match invalid_encoding {
        DecodingError::InvalidEncoding { hint: _ } => (),
        _ => panic!("Expected InvalidEncoding"),
    }
    #[cfg(not(debug_assertions))]
    match invalid_encoding {
        DecodingError::InvalidEncoding => (),
        _ => panic!("Expected InvalidEncoding"),
    }

    // Test Display
    assert!(format!("{}", invalid_encoding).contains("invalid encoding"));
}

/// Test HexError InvalidLength cfg-split
#[cfg(feature = "encoding-hex")]
#[test]
fn hex_error_invalid_length_cfg() {
    #[cfg(debug_assertions)]
    {
        let err = secure_gate::HexError::InvalidLength {
            expected: 32,
            got: 31,
        };
        assert_eq!(
            format!("{}", err),
            "decoded length mismatch: expected 32, got 31"
        );
    }
    #[cfg(not(debug_assertions))]
    {
        let err = secure_gate::HexError::InvalidLength;
        assert_eq!(format!("{}", err), "decoded length mismatch");
    }
}

/// Test Base64Error InvalidLength cfg-split
#[cfg(feature = "encoding-base64")]
#[test]
fn base64_error_invalid_length_cfg() {
    #[cfg(debug_assertions)]
    {
        let err = secure_gate::Base64Error::InvalidLength {
            expected: 32,
            got: 31,
        };
        assert_eq!(
            format!("{}", err),
            "decoded length mismatch: expected 32, got 31"
        );
    }
    #[cfg(not(debug_assertions))]
    {
        let err = secure_gate::Base64Error::InvalidLength;
        assert_eq!(format!("{}", err), "decoded length mismatch");
    }
}

/// Test Bech32Error InvalidLength cfg-split
#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_error_invalid_length_cfg() {
    #[cfg(debug_assertions)]
    {
        let err = secure_gate::Bech32Error::InvalidLength {
            expected: 32,
            got: 31,
        };
        assert_eq!(
            format!("{}", err),
            "decoded length mismatch: expected 32, got 31"
        );
    }
    #[cfg(not(debug_assertions))]
    {
        let err = secure_gate::Bech32Error::InvalidLength;
        assert_eq!(format!("{}", err), "decoded length mismatch");
    }
}

/// Test Bech32Error UnexpectedHrp cfg-split
#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_error_unexpected_hrp_cfg() {
    #[cfg(debug_assertions)]
    {
        let err = secure_gate::Bech32Error::UnexpectedHrp {
            expected: "key".to_string(),
            got: "wrong".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "unexpected HRP: expected key, got wrong"
        );
    }
    #[cfg(not(debug_assertions))]
    {
        let err = secure_gate::Bech32Error::UnexpectedHrp;
        assert_eq!(format!("{}", err), "unexpected HRP");
    }
}
