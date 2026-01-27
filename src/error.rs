// secure-gate\src\error.rs

//! Centralized error types for the secure-gate crate.

/// Error type for slice conversion operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FromSliceError {
    #[error("slice length mismatch")]
    LengthMismatch,
}

#[cfg(feature = "encoding-bech32")]
/// Error type for Bech32 operations (encoding and decoding).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Bech32Error {
    #[error("invalid Human-Readable Part (HRP)")]
    InvalidHrp,
    #[error("bit conversion failed")]
    ConversionFailed,
    #[error("bech32 operation failed")]
    OperationFailed,
    #[error("unexpected HRP: expected {expected}, got {got}")]
    UnexpectedHrp { expected: String, got: String },
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

#[cfg(feature = "encoding-base64")]
/// Error type for Base64 decoding operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Base64Error {
    #[error("invalid base64 string")]
    InvalidBase64,
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

#[cfg(feature = "encoding-hex")]
/// Error type for Hex decoding operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HexError {
    #[error("invalid hex string")]
    InvalidHex,
    #[error("decoded length mismatch: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

/// Unified error type for decoding operations across formats.
#[derive(Clone, Debug, thiserror::Error)]
pub enum DecodingError {
    #[cfg(feature = "encoding-bech32")]
    #[error("invalid bech32 string")]
    InvalidBech32,
    #[cfg(feature = "encoding-base64")]
    #[error("invalid base64 string")]
    InvalidBase64,
    #[cfg(feature = "encoding-hex")]
    #[error("invalid hex string")]
    InvalidHex,
    #[error("invalid encoding: {hint}")]
    InvalidEncoding {
        /// Additional hint for debugging, e.g., "string does not match any supported format. Attempted order: [Bech32, Hex, Base64Url]".
        /// In production, this can be redacted if it risks leaking metadata.
        hint: String,
    },
}
