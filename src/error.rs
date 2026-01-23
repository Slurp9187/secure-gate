// secure-gate\src\error.rs

//! Centralized error types for the secure-gate crate.

/// Error type for slice conversion operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FromSliceError {
    #[error("slice length mismatch: expected {expected}, got {got}")]
    LengthMismatch { expected: usize, got: usize },
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
}

#[cfg(feature = "encoding-base64")]
/// Error type for Base64 decoding operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Base64Error {
    #[error("invalid base64 string")]
    InvalidBase64,
}

#[cfg(feature = "encoding-hex")]
/// Error type for Hex decoding operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HexError {
    #[error("invalid hex string")]
    InvalidHex,
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
    #[error(
        "invalid encoding: string does not match any supported format (bech32, hex, or base64)"
    )]
    InvalidEncoding,
}
