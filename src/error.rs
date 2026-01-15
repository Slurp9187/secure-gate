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

/// Error for slice length mismatches in TryFrom impls.
#[derive(Debug, thiserror::Error)]
#[error("slice length mismatch: expected {expected_len} bytes, got {actual_len} bytes")]
pub struct FromSliceError {
    pub(crate) actual_len: usize,
    pub(crate) expected_len: usize,
}

impl FromSliceError {
    /// Create a new FromSliceError with the actual and expected lengths.
    pub(crate) fn new(actual_len: usize, expected_len: usize) -> Self {
        Self {
            actual_len,
            expected_len,
        }
    }
}
