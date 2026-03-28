//! Centralized error types for the secure-gate crate.
//!
//! Errors are designed with security in mind: debug builds include detailed context
//! (e.g., expected vs. actual lengths, HRP values) to aid development and testing,
//! while release builds use generic messages to avoid leaking sensitive information
//! about decoding failures or secret properties.
//!
//! All decoding-related errors follow this hardening pattern.
//! (Zeroization is handled at the wrapper level — see `Fixed`/`Dynamic` docs.)

use thiserror::Error;

/// Error returned when a byte slice cannot be converted to a fixed-size array.
///
/// In **debug builds** includes expected and actual lengths for development debugging.
/// In **release builds** uses generic messages to prevent leaking expected-length metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FromSliceError {
    #[cfg(debug_assertions)]
    /// Length mismatch in debug builds (detailed).
    #[error("slice length mismatch: expected {expected}, got {actual}")]
    InvalidLength {
        /// Actual slice length in bytes.
        actual: usize,
        /// Expected length in bytes.
        expected: usize,
    },
    #[cfg(not(debug_assertions))]
    /// Length mismatch in release builds (generic).
    #[error("slice length mismatch")]
    InvalidLength,
}

/// Errors produced when decoding Bech32 (BIP-173) or Bech32m (BIP-350) strings.
///
/// *Requires feature `encoding-bech32` or `encoding-bech32m`.*
///
/// In **debug builds** `UnexpectedHrp` and `InvalidLength` carry `expected`/`got`
/// fields for development debugging. In **release builds** these variants are opaque
/// to prevent leaking expected-length or HRP metadata.
#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Bech32Error {
    /// The Human-Readable Part (HRP) is invalid.
    #[error("invalid Human-Readable Part (HRP)")]
    InvalidHrp,
    /// Bit conversion during encoding/decoding failed.
    ///
    /// **Currently unreachable.** After `CheckedHrpstring::new()` succeeds, the
    /// `.byte_iter()` iterator is infallible — all bit-conversion happens during
    /// the `new()` call and any failure surfaces as `OperationFailed` instead.
    /// This variant is preserved as public API for forward compatibility should a
    /// fallible conversion path be introduced in a future release of the `bech32` crate.
    #[error("bit conversion failed")]
    ConversionFailed,
    /// General bech32 operation failure.
    #[error("bech32 operation failed")]
    OperationFailed,
    #[cfg(debug_assertions)]
    /// Unexpected HRP in debug builds (detailed).
    #[error("unexpected HRP: expected {expected}, got {got}")]
    UnexpectedHrp {
        /// Human-readable part that was expected.
        expected: String,
        /// Human-readable part present in the input.
        got: String,
    },
    #[cfg(not(debug_assertions))]
    /// Unexpected HRP in release builds (generic).
    #[error("unexpected HRP")]
    UnexpectedHrp,
    #[cfg(debug_assertions)]
    /// Length mismatch in debug builds (detailed).
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    InvalidLength {
        /// Expected decoded length in bytes.
        expected: usize,
        /// Actual decoded length in bytes.
        got: usize,
    },
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
#[cfg(feature = "encoding-base64")]
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Base64Error {
    /// The string is not valid base64url.
    #[error("invalid base64 string")]
    InvalidBase64,
    #[cfg(debug_assertions)]
    /// Length mismatch in debug builds (detailed).
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    InvalidLength {
        /// Expected decoded length in bytes.
        expected: usize,
        /// Actual decoded length in bytes.
        got: usize,
    },
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
#[cfg(feature = "encoding-hex")]
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum HexError {
    /// The string is not valid hexadecimal.
    #[error("invalid hex string")]
    InvalidHex,
    #[cfg(debug_assertions)]
    /// Length mismatch in debug builds (detailed).
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    InvalidLength {
        /// Expected decoded length in bytes.
        expected: usize,
        /// Actual decoded length in bytes.
        got: usize,
    },
    #[cfg(not(debug_assertions))]
    /// Length mismatch in release builds (generic).
    #[error("decoded length mismatch")]
    InvalidLength,
}

/// Unified error type for multi-format decoding operations.
///
/// Wraps format-specific errors from hex, base64url, bech32, and bech32m decoders.
/// Always available; variants depend on enabled features.
#[derive(Clone, Debug, Error)]
pub enum DecodingError {
    /// Bech32 or Bech32m decoding failed.
    #[cfg(feature = "encoding-bech32")]
    #[error("invalid bech32 string")]
    InvalidBech32(#[source] Bech32Error),
    /// Base64url decoding failed.
    #[cfg(feature = "encoding-base64")]
    #[error("invalid base64 string")]
    InvalidBase64(#[source] Base64Error),
    /// Hexadecimal decoding failed.
    #[cfg(feature = "encoding-hex")]
    #[error("invalid hex string")]
    InvalidHex(#[source] HexError),
    /// Generic encoding failure in debug builds (includes a non-sensitive hint).
    #[cfg(debug_assertions)]
    #[error("invalid encoding: {hint}")]
    InvalidEncoding {
        /// Short hint for developers (debug builds only).
        hint: String,
    },
    #[cfg(not(debug_assertions))]
    /// Generic encoding failure in release builds (opaque).
    #[error("invalid encoding")]
    InvalidEncoding,
}
