//! Centralized error types for the secure-gate crate.
//!
//! # Error types
//!
//! | Type | Produced by | Feature |
//! |------|------------|---------|
//! | [`FromSliceError`] | [`Fixed::try_from(&[u8])`](crate::Fixed) | Always |
//! | [`HexError`] | [`Fixed::try_from_hex`](crate::Fixed::try_from_hex), [`FromHexStr`](crate::FromHexStr) | `encoding-hex` |
//! | [`Base32Error`] | [`Fixed::try_from_base32`](crate::Fixed::try_from_base32), [`FromBase32Str`](crate::FromBase32Str) | `encoding-base32` |
//! | [`Base64Error`] | [`Fixed::try_from_base64url`](crate::Fixed::try_from_base64url), [`FromBase64UrlStr`](crate::FromBase64UrlStr) | `encoding-base64` |
//! | [`Bech32Error`] | `try_from_bech32*`, [`FromBech32Str`](crate::FromBech32Str), [`FromBech32mStr`](crate::FromBech32mStr) | `encoding-bech32` / `encoding-bech32m` |
//!
//! Every type in this module is produced by a function in this crate. There is no
//! unified wrapper enum: a caller decoding several formats owns the union it needs,
//! and nothing here would help it build one.
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
//!   need a wildcard arm. This is also what lets the crate ship a variant only
//!   once something produces it, rather than reserving one in advance.
//! - **No derive macros.** [`Display`](core::fmt::Display) and
//!   [`Error`](core::error::Error) are written out by hand below. The messages are
//!   fixed strings and two `usize` fields, which is not enough work to justify
//!   putting a proc-macro (and `syn`, `quote`, `proc-macro2`) in the dependency
//!   graph of every downstream build.
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
        match *self {
            Self::InvalidLength { expected, got } => {
                write!(f, "slice length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl core::error::Error for FromSliceError {}

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
    /// General bech32 operation failure (malformed string or checksum mismatch).
    ///
    /// This is where bit-conversion failures surface too: all bit conversion
    /// happens inside `CheckedHrpstring::new()`, and the `.byte_iter()` that
    /// follows a successful `new()` is infallible.
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
        match *self {
            Self::InvalidHrp => f.write_str("invalid Human-Readable Part (HRP)"),
            Self::OperationFailed => f.write_str("bech32 operation failed"),
            Self::UnexpectedHrp => f.write_str("unexpected HRP"),
            Self::InvalidLength { expected, got } => {
                write!(f, "decoded length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
impl core::error::Error for Bech32Error {}

/// Errors produced when decoding Base32 (RFC 4648 §6, uppercase, unpadded) strings.
///
/// *Requires feature `encoding-base32`.*
///
/// Variant shapes are identical in debug and release builds; only numeric
/// length metadata is carried.
#[cfg(feature = "encoding-base32")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Base32Error {
    /// The string is not valid Base32 (wrong alphabet, wrong case, padding, or
    /// an impossible length).
    InvalidBase32,
    /// The decoded payload length does not match the target type's length.
    #[non_exhaustive]
    InvalidLength {
        /// Number of bytes the target type requires.
        expected: usize,
        /// Number of bytes actually decoded.
        got: usize,
    },
}

#[cfg(feature = "encoding-base32")]
impl fmt::Display for Base32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidBase32 => f.write_str("invalid base32 string"),
            Self::InvalidLength { expected, got } => {
                write!(f, "decoded length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

#[cfg(feature = "encoding-base32")]
impl core::error::Error for Base32Error {}

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
        match *self {
            Self::InvalidBase64 => f.write_str("invalid base64 string"),
            Self::InvalidLength { expected, got } => {
                write!(f, "decoded length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

#[cfg(feature = "encoding-base64")]
impl core::error::Error for Base64Error {}

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
        match *self {
            Self::InvalidHex => f.write_str("invalid hex string"),
            Self::InvalidLength { expected, got } => {
                write!(f, "decoded length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

#[cfg(feature = "encoding-hex")]
impl core::error::Error for HexError {}
