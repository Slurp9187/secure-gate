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
//!
//! # 0.8 LTS note: hand-written impls instead of `thiserror`
//!
//! Unlike the 0.9 line, this branch does not use `thiserror`: its `no_std`
//! support requires `core::error::Error` (Rust 1.81+), above this branch's
//! MSRV of 1.70. `Display` is implemented manually for every build, and
//! `std::error::Error` (including `source()` chaining on [`DecodingError`])
//! is provided behind the `std` feature.

use core::fmt;

/// Error returned when a byte slice cannot be converted to a fixed-size array.
///
/// Carries the expected and actual lengths in all build profiles. Lengths are
/// public protocol parameters, not secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromSliceError {
    /// The slice length does not match the target array length.
    #[non_exhaustive]
    InvalidLength {
        /// Number of bytes the target array requires.
        expected: usize,
        /// Number of bytes actually provided.
        got: usize,
    },
}

impl fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, got } => {
                write!(f, "slice length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromSliceError {}

/// Errors produced when decoding Bech32 (BIP-173) or Bech32m (BIP-350) strings.
///
/// *Requires feature `encoding-bech32` or `encoding-bech32m`.*
///
/// Variant shapes are identical in debug and release builds. No input-derived
/// strings (such as the received HRP) are ever captured — the caller already
/// holds the input and the expected HRP.
#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bech32Error {
    /// The Human-Readable Part (HRP) is invalid.
    InvalidHrp,
    /// Bit conversion during encoding/decoding failed.
    ///
    /// **Currently unreachable.** After `CheckedHrpstring::new()` succeeds, the
    /// `.byte_iter()` iterator is infallible — all bit-conversion happens during
    /// the `new()` call and any failure surfaces as `OperationFailed` instead.
    /// This variant is preserved as public API for forward compatibility should a
    /// fallible conversion path be introduced in a future release of the `bech32` crate.
    ConversionFailed,
    /// General bech32 operation failure (malformed string or checksum mismatch).
    OperationFailed,
    /// The decoded HRP does not match the HRP the caller required.
    ///
    /// The received HRP is deliberately not captured — it is input-derived text.
    /// The caller passed the expected HRP and holds the input string.
    UnexpectedHrp,
    /// The decoded payload length does not match the target type's length.
    #[non_exhaustive]
    InvalidLength {
        /// Number of bytes the target type requires.
        expected: usize,
        /// Number of bytes actually decoded.
        got: usize,
    },
}

#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
impl fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHrp => f.write_str("invalid Human-Readable Part (HRP)"),
            Self::ConversionFailed => f.write_str("bit conversion failed"),
            Self::OperationFailed => f.write_str("bech32 operation failed"),
            Self::UnexpectedHrp => f.write_str("unexpected HRP"),
            Self::InvalidLength { expected, got } => {
                write!(f, "decoded length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

#[cfg(all(
    feature = "std",
    any(feature = "encoding-bech32", feature = "encoding-bech32m")
))]
impl std::error::Error for Bech32Error {}

/// Errors produced when decoding base64url strings.
///
/// *Requires feature `encoding-base64`.*
///
/// Variant shapes are identical in debug and release builds; only numeric
/// length metadata is carried.
#[cfg(feature = "encoding-base64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Base64Error {
    /// The string is not valid base64url.
    InvalidBase64,
    /// The decoded payload length does not match the target type's length.
    #[non_exhaustive]
    InvalidLength {
        /// Number of bytes the target type requires.
        expected: usize,
        /// Number of bytes actually decoded.
        got: usize,
    },
}

#[cfg(feature = "encoding-base64")]
impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBase64 => f.write_str("invalid base64 string"),
            Self::InvalidLength { expected, got } => {
                write!(f, "decoded length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

#[cfg(all(feature = "std", feature = "encoding-base64"))]
impl std::error::Error for Base64Error {}

/// Errors produced when decoding hexadecimal strings.
///
/// *Requires feature `encoding-hex`.*
///
/// Variant shapes are identical in debug and release builds; only numeric
/// length metadata is carried.
#[cfg(feature = "encoding-hex")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HexError {
    /// The string is not valid hexadecimal.
    InvalidHex,
    /// The decoded payload length does not match the target type's length.
    #[non_exhaustive]
    InvalidLength {
        /// Number of bytes the target type requires.
        expected: usize,
        /// Number of bytes actually decoded.
        got: usize,
    },
}

#[cfg(feature = "encoding-hex")]
impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex => f.write_str("invalid hex string"),
            Self::InvalidLength { expected, got } => {
                write!(f, "decoded length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

#[cfg(all(feature = "std", feature = "encoding-hex"))]
impl std::error::Error for HexError {}

/// Unified error type for multi-format decoding operations.
///
/// Wraps format-specific errors from hex, base64url, bech32, and bech32m decoders.
/// Always available; variants depend on enabled features. Like the format-specific
/// errors it wraps, this type is heap-free, `Copy`, and build-invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodingError {
    /// The input is not valid Bech32.
    #[cfg(feature = "encoding-bech32")]
    InvalidBech32(Bech32Error),
    /// The input is not valid Base64url.
    #[cfg(feature = "encoding-base64")]
    InvalidBase64(Base64Error),
    /// The input is not valid hexadecimal.
    #[cfg(feature = "encoding-hex")]
    InvalidHex(HexError),
    /// The encoding could not be identified.
    ///
    /// Deliberately carries no hint text — free-form diagnostics derived from
    /// the input would embed input data in the error value.
    InvalidEncoding,
}

impl fmt::Display for DecodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "encoding-bech32")]
            Self::InvalidBech32(_) => f.write_str("invalid bech32 string"),
            #[cfg(feature = "encoding-base64")]
            Self::InvalidBase64(_) => f.write_str("invalid base64 string"),
            #[cfg(feature = "encoding-hex")]
            Self::InvalidHex(_) => f.write_str("invalid hex string"),
            Self::InvalidEncoding => f.write_str("invalid encoding"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "encoding-bech32")]
            Self::InvalidBech32(inner) => Some(inner),
            #[cfg(feature = "encoding-base64")]
            Self::InvalidBase64(inner) => Some(inner),
            #[cfg(feature = "encoding-hex")]
            Self::InvalidHex(inner) => Some(inner),
            Self::InvalidEncoding => None,
        }
    }
}
