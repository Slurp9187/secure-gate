//! Tests for error types defined in the `error.rs` module.

use secure_gate::{Fixed, FromSliceError};

#[cfg(feature = "encoding-bech32")]
use secure_gate::Bech32EncodingError;

/// Test FromSliceError Debug output
#[test]
fn from_slice_error_debug() {
    let one: &[u8] = &[1];
    let err_result: Result<Fixed<[u8; 4]>, FromSliceError> = Fixed::try_from(one);
    match err_result {
        Err(e) => {
            let debug_str = format!("{:?}", e);
            assert!(debug_str.contains("FromSliceError"));
            assert!(debug_str.contains("actual_len: 1"));
            assert!(debug_str.contains("expected_len: 4"));
        }
        Ok(_) => panic!("Expected error"),
    }
}

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
