//! Centralized error types for the secure-gate crate.

#[cfg(feature = "encoding-bech32")]
/// Error type for Bech32 encoding operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Bech32EncodingError {
    #[error("invalid Human-Readable Part (HRP)")]
    InvalidHrp,
    #[error("encoding operation failed")]
    EncodingFailed,
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
