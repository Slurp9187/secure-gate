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
//! # Design: build-invariant, heap-free, forward-compatible
//!
//! - **Identical shapes in debug and release builds.** No variant is gated on
//!   `cfg(debug_assertions)`, so code that matches on these enums compiles and
//!   behaves the same under every profile.
//! - **No heap data.** Errors carry at most `usize` length metadata; they never
//!   contain payload bytes, HRP strings, or other input-derived text. All error
//!   types are `Copy` and work without `alloc`.
//! - **`#[non_exhaustive]`.** Variants (and fields of struct variants) may be
//!   added in future releases without a semver-major bump; downstream matches
//!   need a wildcard arm.
//!
//! # Security: what errors may reveal
//!
//! `InvalidLength` variants carry the expected and actual byte counts in all
//! builds. Expected lengths are compile-time protocol parameters (key sizes,
//! nonce sizes) and actual lengths derive from the caller's own input, so
//! neither is treated as secret — this matches the crate's threat model
//! (see SECURITY.md). Genuinely input-derived strings (received HRPs, encoding
//! hints) are **never** captured, in any build. If even coarse error categories
//! are sensitive in your deployment, redact errors at the logging boundary.

use thiserror::Error;

/// Error returned when a byte slice cannot be converted to a fixed-size array.
///
/// Carries the expected and actual lengths in all build profiles. Lengths are
/// public protocol parameters, not secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FromSliceError {
    /// The slice length does not match the target array length.
    #[error("slice length mismatch: expected {expected}, got {got}")]
    #[non_exhaustive]
    InvalidLength {
        /// Number of bytes the target array requires.
        expected: usize,
        /// Number of bytes actually provided.
        got: usize,
    },
}

/// Errors produced when decoding Bech32 (BIP-173) or Bech32m (BIP-350) strings.
///
/// *Requires feature `encoding-bech32` or `encoding-bech32m`.*
///
/// Variant shapes are identical in debug and release builds. No input-derived
/// strings (such as the received HRP) are ever captured — the caller already
/// holds the input and the expected HRP.
#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
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
    /// General bech32 operation failure (malformed string or checksum mismatch).
    #[error("bech32 operation failed")]
    OperationFailed,
    /// The decoded HRP does not match the HRP the caller required.
    ///
    /// The received HRP is deliberately not captured — it is input-derived text.
    /// The caller passed the expected HRP and holds the input string.
    #[error("unexpected HRP")]
    UnexpectedHrp,
    /// The decoded payload length does not match the target type's length.
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    #[non_exhaustive]
    InvalidLength {
        /// Number of bytes the target type requires.
        expected: usize,
        /// Number of bytes actually decoded.
        got: usize,
    },
}

/// Errors produced when decoding base64url strings.
///
/// *Requires feature `encoding-base64`.*
///
/// Variant shapes are identical in debug and release builds; only numeric
/// length metadata is carried.
#[cfg(feature = "encoding-base64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Base64Error {
    /// The string is not valid base64url.
    #[error("invalid base64 string")]
    InvalidBase64,
    /// The decoded payload length does not match the target type's length.
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    #[non_exhaustive]
    InvalidLength {
        /// Number of bytes the target type requires.
        expected: usize,
        /// Number of bytes actually decoded.
        got: usize,
    },
}

/// Errors produced when decoding hexadecimal strings.
///
/// *Requires feature `encoding-hex`.*
///
/// Variant shapes are identical in debug and release builds; only numeric
/// length metadata is carried.
#[cfg(feature = "encoding-hex")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum HexError {
    /// The string is not valid hexadecimal.
    #[error("invalid hex string")]
    InvalidHex,
    /// The decoded payload length does not match the target type's length.
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    #[non_exhaustive]
    InvalidLength {
        /// Number of bytes the target type requires.
        expected: usize,
        /// Number of bytes actually decoded.
        got: usize,
    },
}

/// Unified error type for multi-format decoding operations.
///
/// Wraps format-specific errors from hex, base64url, bech32, and bech32m decoders.
/// Always available; variants depend on enabled features. Like the format-specific
/// errors it wraps, this type is heap-free, `Copy`, and build-invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
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
    /// The encoding could not be identified.
    ///
    /// Deliberately carries no hint text — free-form diagnostics derived from
    /// the input would embed input data in the error value.
    #[error("invalid encoding")]
    InvalidEncoding,
}
