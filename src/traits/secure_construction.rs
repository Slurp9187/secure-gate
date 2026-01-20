//! Sealed marker trait for secure construction (random/decoding).

/// Sealed marker trait for secure construction (random/decoding).
#[allow(dead_code)]
pub trait Sealed {}

#[allow(dead_code)]
pub trait SecureConstruction: Sealed {
    /// Generate a secure random instance (panics on failure).
    #[cfg(feature = "rand")]
    fn from_random() -> Self;

    /// Decode from hex string (panics on invalid/length mismatch).
    #[cfg(feature = "encoding-hex")]
    fn from_hex(s: &str) -> Self;

    /// Decode from base64 string (panics on invalid/length mismatch).
    #[cfg(feature = "encoding-base64")]
    fn from_base64(s: &str) -> Self;

    /// Decode from bech32 string with HRP (panics on invalid).
    #[cfg(feature = "encoding-bech32")]
    fn from_bech32(s: &str, hrp: &str) -> Self;
}
