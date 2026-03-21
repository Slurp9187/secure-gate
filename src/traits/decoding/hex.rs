//! Hexadecimal decoding trait.
//!
//! This trait provides secure, explicit decoding of hexadecimal strings
//! to byte vectors. It is designed for handling untrusted input in
//! cryptographic contexts, such as decoding hex-encoded keys or nonces.
//!
//! Requires the `encoding-hex` feature.
//!
//! # Security Notes
//!
//! - Treat all input as untrusted**: validate hex strings upstream before wrapping in secrets. Invalid input fails immediately.
//!   in secrets. Invalid hex may indicate tampering or injection attempts.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in [`Fixed`](crate::Fixed) or
//!   [`Dynamic`](crate::Dynamic) to store as a secret.
//! - **Case-insensitive**: Accepts both uppercase and lowercase hex digits.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-hex")]
//! use secure_gate::{FromHexStr, Fixed};
//! # #[cfg(feature = "encoding-hex")]
//! {
//! let bytes = "01234567".try_from_hex().unwrap();
//! assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67]);
//!
//! // Wrap result in a secret immediately
//! let secret: Fixed<[u8; 4]> = Fixed::try_from_hex("deadbeef").unwrap();
//!
//! // Error on invalid input
//! assert!("xyz!".try_from_hex().is_err());
//! }
//! ```
#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

#[cfg(feature = "encoding-hex")]
use crate::error::HexError;

/// Extension trait for decoding hexadecimal strings into byte vectors.
///
/// *Requires feature `encoding-hex`.*
///
/// Blanket-implemented for all `AsRef<str>` types. Treat all input as untrusted;
/// validate lengths and content upstream before wrapping decoded bytes in secrets.
#[cfg(feature = "encoding-hex")]
pub trait FromHexStr {
    /// Decodes a hexadecimal string into a byte vector.
    ///
    /// Case-insensitive; rejects odd-length strings and invalid characters.
    ///
    /// # Errors
    ///
    /// - [`HexError::InvalidHex`] — non-hex characters or odd-length input.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::FromHexStr;
    ///
    /// let bytes = "deadbeef".try_from_hex()?;
    /// assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
    ///
    /// assert!("xyz!".try_from_hex().is_err()); // invalid chars
    /// assert!("a".try_from_hex().is_err());    // odd length
    /// # Ok::<(), secure_gate::HexError>(())
    /// ```
    fn try_from_hex(&self) -> Result<Vec<u8>, HexError>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(feature = "encoding-hex")]
impl<T: AsRef<str> + ?Sized> FromHexStr for T {
    fn try_from_hex(&self) -> Result<Vec<u8>, HexError> {
        hex_crate::decode(self.as_ref()).map_err(|_| HexError::InvalidHex)
    }
}
