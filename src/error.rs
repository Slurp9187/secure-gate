//! Centralized error types for the secure-gate crate.
//!
//! Errors are designed with security in mind: debug builds include detailed context
//! (e.g., expected vs. actual lengths, HRP values) to aid development and testing,
//! while release builds use generic messages to avoid leaking sensitive information
//! about decoding failures or secret properties.
//!
//! All decoding-related errors follow this hardening pattern.

use thiserror::Error;

/// Error type for slice conversion operations.
///
/// Used when converting slices to fixed-size arrays fails due to length mismatch.
/// Always available.
///
/// # Examples
///
/// ```rust
/// use secure_gate::Fixed;
///
/// // This succeeds with correct length
/// let result = Fixed::<[u8; 2]>::try_from(&[1u8, 2] as &[u8]);
/// assert!(result.is_ok());
///
/// // Length mismatch returns an error in release builds (panics in debug builds).
/// // In release mode, this returns FromSliceError::LengthMismatch:
/// #[cfg(not(debug_assertions))]
/// {
///     let bad_result = Fixed::<[u8; 2]>::try_from(&[1u8] as &[u8]);  // Length 1 != 2
///     assert!(matches!(bad_result, Err(FromSliceError::LengthMismatch)));
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FromSliceError {
    /// The slice length does not match the expected fixed size.
    #[error("slice length mismatch")]
    LengthMismatch,
}

/// Error type for Bech32 and Bech32m operations (encoding and decoding).
///
/// Debug builds provide detailed context (e.g., expected vs. actual HRP, lengths);
/// release builds use generic messages to prevent information leaks.
///
/// Requires `encoding-bech32` or `encoding-bech32m` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-bech32")]
/// use secure_gate::{FromBech32Str, Bech32Error};
///
/// # #[cfg(feature = "encoding-bech32")]
/// {
/// let result = "invalid".try_from_bech32();
/// assert!(result.is_err());
/// # }
/// ```
#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Bech32Error {
    /// The Human-Readable Part (HRP) is invalid.
    #[error("invalid Human-Readable Part (HRP)")]
    InvalidHrp,

    /// Bit conversion during encoding/decoding failed.
    #[error("bit conversion failed")]
    ConversionFailed,

    /// General bech32 operation failure.
    #[error("bech32 operation failed")]
    OperationFailed,

    #[cfg(debug_assertions)]
    /// Unexpected HRP in debug builds (detailed).
    #[error("unexpected HRP: expected {expected}, got {got}")]
    UnexpectedHrp { expected: String, got: String },

    #[cfg(not(debug_assertions))]
    /// Unexpected HRP in release builds (generic).
    #[error("unexpected HRP")]
    UnexpectedHrp,

    #[cfg(debug_assertions)]
    /// Length mismatch in debug builds (detailed).
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[cfg(not(debug_assertions))]
    /// Length mismatch in release builds (generic).
    #[error("decoded length mismatch")]
    InvalidLength,
}

/// Error type for Base64url decoding operations.
///
/// Debug builds provide detailed context (e.g., expected vs. actual lengths);
/// release builds use generic messages to prevent information leaks.
///
/// Requires `encoding-base64` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-base64")]
/// use secure_gate::{FromBase64UrlStr, Base64Error};
///
/// # #[cfg(feature = "encoding-base64")]
/// {
/// let result = "invalid!".try_from_base64url();
/// assert!(matches!(result, Err(Base64Error::InvalidBase64)));
/// # }
/// ```
#[cfg(feature = "encoding-base64")]
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Base64Error {
    /// The string is not valid base64url.
    #[error("invalid base64 string")]
    InvalidBase64,

    #[cfg(debug_assertions)]
    /// Length mismatch in debug builds (detailed).
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[cfg(not(debug_assertions))]
    /// Length mismatch in release builds (generic).
    #[error("decoded length mismatch")]
    InvalidLength,
}

/// Error type for Hex decoding operations.
///
/// Debug builds provide detailed context (e.g., expected vs. actual lengths);
/// release builds use generic messages to prevent information leaks.
///
/// Requires `encoding-hex` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-hex")]
/// use secure_gate::{FromHexStr, HexError};
///
/// # #[cfg(feature = "encoding-hex")]
/// {
/// let result = "invalid!".try_from_hex();
/// assert!(matches!(result, Err(HexError::InvalidHex)));
/// # }
/// ```
#[cfg(feature = "encoding-hex")]
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum HexError {
    /// The string is not valid hexadecimal.
    #[error("invalid hex string")]
    InvalidHex,

    #[cfg(debug_assertions)]
    /// Length mismatch in debug builds (detailed).
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[cfg(not(debug_assertions))]
    /// Length mismatch in release builds (generic).
    #[error("decoded length mismatch")]
    InvalidLength,
}

/// Unified error type for decoding operations across formats.
///
/// Combines errors from different encoding schemes. Debug builds include
/// format-specific hints for development; release builds use generic messages
/// to prevent leaking metadata about secret formats or lengths.
///
/// Always available, but variants depend on enabled features.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-hex")]
/// use secure_gate::{FromHexStr, DecodingError};
///
/// # #[cfg(feature = "encoding-hex")]
/// {
/// let result = "invalid!".try_from_hex();
/// // Would map to DecodingError variant if using unified error handling
/// # }
/// ```
#[derive(Clone, Debug, Error)]
pub enum DecodingError {
    #[cfg(feature = "encoding-bech32")]
    /// Invalid bech32 or bech32m string.
    #[error("invalid bech32 string")]
    InvalidBech32(#[source] Bech32Error),

    #[cfg(feature = "encoding-base64")]
    /// Invalid base64url string.
    #[error("invalid base64 string")]
    InvalidBase64(#[source] Base64Error),

    #[cfg(feature = "encoding-hex")]
    /// Invalid hex string.
    #[error("invalid hex string")]
    InvalidHex(#[source] HexError),

    #[cfg(debug_assertions)]
    /// Invalid encoding with debug hint (shows attempted formats/order).
    #[error("invalid encoding: {hint}")]
    InvalidEncoding { hint: String },

    #[cfg(not(debug_assertions))]
    /// Invalid encoding (generic message).
    #[error("invalid encoding")]
    InvalidEncoding,
}
