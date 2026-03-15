//! Hexadecimal decoding trait.
//!
//! This trait provides secure, explicit decoding of hexadecimal strings
//! to byte vectors. It is designed for handling untrusted input in
//! cryptographic contexts, such as decoding hex-encoded keys or nonces.
//!
//! Requires the `encoding-hex` feature.
//!
//! # Security Notes
//! - **Untrusted input**: Always treat decoded data as potentially malicious.
//!   Use fallible methods and validate lengths/content after decoding.
//! - **Invalid input**: May indicate tampering, injection attempts, or errors —
//!   log/handle carefully without leaking details.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in `Fixed` or `Dynamic` for secrets.
//! - **Case insensitive**: Accepts both upper and lower case hex digits.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-hex")]
//! use secure_gate::FromHexStr;
//!
//! # #[cfg(feature = "encoding-hex")]
//! {
//! let hex = "01234567";
//! let bytes = hex.try_from_hex().unwrap();
//! assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67]);
//! # }
//! ```
#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

#[cfg(feature = "encoding-hex")]
use crate::error::HexError;

/// Extension trait for decoding hex strings to byte data.
///
/// Requires `encoding-hex` feature.
///
/// # Security Warning
///
/// Treat all input as untrusted — invalid hex may indicate tampering.
/// Always use the fallible `try_from_hex` and handle errors securely.
#[cfg(feature = "encoding-hex")]
pub trait FromHexStr {
    /// Fallibly decodes a hex string to bytes.
    ///
    /// Returns [`HexError::InvalidHex`] for invalid characters or odd length.
    /// Requires `encoding-hex` feature.
    fn try_from_hex(&self) -> Result<Vec<u8>, HexError>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(feature = "encoding-hex")]
impl<T: AsRef<str> + ?Sized> FromHexStr for T {
    fn try_from_hex(&self) -> Result<Vec<u8>, HexError> {
        hex_crate::decode(self.as_ref()).map_err(|_| HexError::InvalidHex)
    }
}
