//! Hexadecimal decoding trait.
//!
//! > **Import path:** `use secure_gate::FromHexStr;`
//!
//! This trait provides secure, explicit decoding of hexadecimal strings
//! to byte vectors. It is designed for handling untrusted input in
//! cryptographic contexts, such as decoding hex-encoded keys or nonces.
//!
//! Requires the `encoding-hex` feature.
//!
//! # Security Notes
//!
//! - **Treat all input as untrusted**: validate hex strings upstream before wrapping
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
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
use crate::error::HexError;

/// Extension trait for decoding hexadecimal strings into byte vectors.
///
/// *Requires features `encoding-hex` and `alloc`.*
///
/// Blanket-implemented for all `AsRef<str>` types. Returns `Vec<u8>` — requires heap
/// allocation. For no-alloc targets, use `Fixed::try_from_hex` instead, which decodes
/// directly into a stack-allocated `[u8; N]` buffer.
///
/// Treat all input as untrusted; validate lengths and content upstream before wrapping
/// decoded bytes in secrets.
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
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
    fn try_from_hex(&self) -> Result<alloc::vec::Vec<u8>, HexError>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
// Returns Vec<u8> — alloc required.
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
impl<T: AsRef<str> + ?Sized> FromHexStr for T {
    fn try_from_hex(&self) -> Result<alloc::vec::Vec<u8>, HexError> {
        base16ct::mixed::decode_vec(self.as_ref().as_bytes()).map_err(|_| HexError::InvalidHex)
    }
}
