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
