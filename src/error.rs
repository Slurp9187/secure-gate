//! Centralized error types for the secure-gate crate.
//!
//! Errors are designed with security in mind: debug builds include detailed context
//! (e.g., expected vs. actual lengths, HRP values) to aid development and testing,
//! while release builds use generic messages to avoid leaking sensitive information
//! about decoding failures or secret properties.
//!
//! All decoding-related errors follow this hardening pattern.
//!
//! # Implementation Notes
//!
//! In **debug builds** length-mismatch and HRP-validation variants carry structured
//! fields (`expected`/`got`) to aid development. In **release builds** those variants
//! are opaque — preventing expected-length or HRP metadata from leaking to attackers.
//! The `#[cfg(debug_assertions)]` split is used throughout for this purpose.

use thiserror::Error;

/// Error returned when a byte slice cannot be converted to a fixed-size array.
///
/// Always available. In **debug builds** the conversion panics with full context
/// instead of returning this error (for development ergonomics). In **release
/// builds** this variant is returned to prevent leaking expected-length metadata.
///
/// # Examples
///
/// ```rust
/// use secure_gate::{Fixed, FromSliceError};
///
/// // Correct length — succeeds.
/// let ok = Fixed::<[u8; 2]>::try_from(&[1u8, 2] as &[u8]);
/// assert!(ok.is_ok());
///
/// // Wrong length — returns error in release builds; panics in debug builds.
/// #[cfg(not(debug_assertions))]
/// {
///     let err = Fixed::<[u8; 2]>::try_from(&[1u8] as &[u8]);
///     assert!(matches!(err, Err(FromSliceError::LengthMismatch)));
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FromSliceError {
    /// The slice length does not match the expected fixed size.
    #[error("slice length mismatch")]
    LengthMismatch,
}

/// Errors produced when decoding Bech32 (BIP-173) or Bech32m (BIP-350) strings.
///
/// *Requires feature `encoding-bech32` or `encoding-bech32m`.*
///
/// In **debug builds** `UnexpectedHrp` and `InvalidLength` carry `expected`/`got`
/// fields for development debugging. In **release builds** these variants are opaque
/// to prevent leaking expected-length or HRP metadata.
///
/// # Examples
///
/// ```rust
/// use secure_gate::{FromBech32Str, Bech32Error};
///
/// match "invalid".try_from_bech32() {
///     Err(Bech32Error::InvalidHrp)           => { /* invalid HRP characters */ }
///     Err(Bech32Error::UnexpectedHrp { .. }) => { /* HRP did not match expected */ }
///     Err(Bech32Error::InvalidLength { .. }) => { /* decoded length mismatch */ }
///     Err(Bech32Error::ConversionFailed)     => { /* bit-conversion failure */ }
///     Err(Bech32Error::OperationFailed)      => { /* other bech32 failure */ }
///     Ok(_) => unreachable!(),
/// }
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

/// Errors produced when decoding base64url strings.
///
/// *Requires feature `encoding-base64`.*
///
/// In **debug builds** `InvalidLength` carries `expected`/`got` fields for
/// development debugging. In **release builds** this variant is opaque to
/// prevent leaking expected-length metadata.
///
/// # Examples
///
/// ```rust
/// use secure_gate::{FromBase64UrlStr, Base64Error};
///
/// match "invalid!".try_from_base64url() {
///     Err(Base64Error::InvalidBase64)        => { /* invalid characters */ }
///     Err(Base64Error::InvalidLength { .. }) => { /* wrong decoded length */ }
///     Ok(_) => unreachable!(),
/// }
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

/// Errors produced when decoding hexadecimal strings.
///
/// *Requires feature `encoding-hex`.*
///
/// In **debug builds** `InvalidLength` carries `expected`/`got` fields for
/// development debugging. In **release builds** this variant is opaque to
/// prevent leaking expected-length metadata.
///
/// # Examples
///
/// ```rust
/// use secure_gate::{FromHexStr, HexError};
///
/// match "invalid!".try_from_hex() {
///     Err(HexError::InvalidHex)            => { /* non-hex characters */ }
///     Err(HexError::InvalidLength { .. })  => { /* wrong decoded length */ }
///     Ok(_) => unreachable!(),
/// }
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

/// Unified error type for multi-format decoding operations.
///
/// Wraps format-specific errors from hex, base64url, bech32, and bech32m decoders.
/// Always available; variants depend on enabled features.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-hex")]
/// use secure_gate::{DecodingError, HexError};
/// # #[cfg(feature = "encoding-hex")]
/// {
/// let err = DecodingError::InvalidHex(HexError::InvalidHex);
/// assert!(matches!(err, DecodingError::InvalidHex(_)));
/// }
/// ```
///
/// # Implementation Notes
///
/// `DecodingError` does not derive `PartialEq` because the `#[source]`-annotated
/// variants wrap nested error types (`HexError`, `Base64Error`, `Bech32Error`)
/// that may not implement `PartialEq` consistently across all feature combinations.
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
