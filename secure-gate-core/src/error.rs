//! Centralized error types for the secure-gate crate.
//!
//! # Error types
//!
//! | Type | Produced by | Feature |
//! |------|------------|---------|
//! | [`FromSliceError`] | [`Fixed::try_from(&[u8])`](crate::Fixed) | Always |
//! | [`HexError`] | [`Fixed::try_from_hex`](crate::Fixed::try_from_hex), [`FromHexStr`](crate::FromHexStr) | `encoding-hex` |
//! | [`Base64Error`] | [`Fixed::try_from_base64url`](crate::Fixed::try_from_base64url), [`FromBase64UrlStr`](crate::FromBase64UrlStr) | `encoding-base64` |
//! | [`Bech32Error`] | `try_from_bech32*`, [`FromBech32Str`](crate::FromBech32Str), [`FromBech32mStr`](crate::FromBech32mStr) | `encoding-bech32` / `encoding-bech32m` |
//! | [`DecodingError`] | Unified wrapper for all above | Always |
//!
//! # Security: debug vs release error metadata
//!
//! In **debug builds** (`cfg(debug_assertions)`), decoding errors include detailed
//! hints — expected vs actual lengths, received HRP values — to aid development.
//! In **release builds** these details are stripped to prevent length/HRP oracles.
//!
//! Prefer `Display` (`{}`) over `Debug` (`{:?}`) when logging errors in production —
//! `Debug` may expose struct fields in debug builds.
//!
//! See [SECURITY.md — Error Metadata](https://github.com/Slurp9187/secure-gate/blob/main/secure-gate-core/SECURITY.md#error-metadata-debug-vs-release)
//! for full guidance.

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
        /// Number of bytes actually provided.
        actual: usize,
        /// Number of bytes the target array requires.
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
        /// The HRP the caller required.
        expected: String,
        /// The HRP found in the input string.
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
        /// Number of bytes the target type requires.
        expected: usize,
        /// Number of bytes actually decoded.
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
        /// Number of bytes the target type requires.
        expected: usize,
        /// Number of bytes actually decoded.
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
        /// Number of bytes the target type requires.
        expected: usize,
        /// Number of bytes actually decoded.
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
    /// The input is not valid Bech32.
    #[cfg(feature = "encoding-bech32")]
    #[error("invalid bech32 string")]
    InvalidBech32(#[source] Bech32Error),
    /// The input is not valid Base64url.
    #[cfg(feature = "encoding-base64")]
    #[error("invalid base64 string")]
    InvalidBase64(#[source] Base64Error),
    /// The input is not valid hexadecimal.
    #[cfg(feature = "encoding-hex")]
    #[error("invalid hex string")]
    InvalidHex(#[source] HexError),
    /// Encoding could not be identified (debug builds include a human-readable hint).
    #[cfg(debug_assertions)]
    #[error("invalid encoding: {hint}")]
    InvalidEncoding {
        /// Free-form description of the failure (debug builds only).
        hint: String,
    },
    /// Encoding could not be identified (release builds omit details).
    #[cfg(not(debug_assertions))]
    #[error("invalid encoding")]
    InvalidEncoding,
}
