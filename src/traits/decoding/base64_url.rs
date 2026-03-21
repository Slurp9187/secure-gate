//! URL-safe Base64 decoding trait.
//!
//! This trait provides secure, explicit decoding of base64url-encoded strings
//! (URL-safe alphabet, no padding) to byte vectors. It is designed for handling
//! untrusted input in cryptographic contexts, such as decoding encoded keys or tokens.
//!
//! Requires the `encoding-base64` feature.
//!
//! # Security Notes
//!
//! - **Treat all input as untrusted**: validate base64url strings upstream before
//!   wrapping in secrets. Invalid input may indicate tampering or injection attempts.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in [`Fixed`](crate::Fixed) or
//!   [`Dynamic`](crate::Dynamic) to store as a secret.
//! - **Strict validation**: URL-safe alphabet, no padding, per RFC 4648 §5. Invalid input fails immediately.
//! - **URL-safe alphabet**: Uses `-` and `_` instead of `+` and `/`.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-base64")]
//! use secure_gate::{FromBase64UrlStr, Fixed};
//! # #[cfg(feature = "encoding-base64")]
//! {
//! // "AQIDBA" decodes to [1, 2, 3, 4]
//! let bytes = "AQIDBA".try_from_base64url().unwrap();
//! assert_eq!(bytes, vec![1, 2, 3, 4]);
//!
//! // Wrap result in a secret immediately
//! let secret: Fixed<[u8; 3]> = Fixed::try_from_base64url("AQID").unwrap();
//!
//! // Error on invalid input
//! assert!("!!!".try_from_base64url().is_err());
//! }
//! ```
#[cfg(feature = "encoding-base64")]
use ::base64 as base64_crate;

#[cfg(feature = "encoding-base64")]
use base64_crate::engine::general_purpose::URL_SAFE_NO_PAD;

#[cfg(feature = "encoding-base64")]
use base64_crate::Engine;

#[cfg(feature = "encoding-base64")]
use crate::error::Base64Error;

/// Extension trait for decoding URL-safe base64 strings into byte vectors.
///
/// *Requires feature `encoding-base64`.*
///
/// Blanket-implemented for all `AsRef<str>` types. Uses the RFC 4648 URL-safe
/// alphabet without `=` padding. Treat all input as untrusted; validate lengths
/// and content upstream before wrapping decoded bytes in secrets.
#[cfg(feature = "encoding-base64")]
pub trait FromBase64UrlStr {
    /// Decodes a URL-safe base64 string (no padding) into a byte vector.
    ///
    /// # Errors
    ///
    /// - [`Base64Error::InvalidBase64`] — invalid characters or unexpected padding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::FromBase64UrlStr;
    ///
    /// // "AQIDBA" decodes to [1, 2, 3, 4]
    /// let bytes = "AQIDBA".try_from_base64url()?;
    /// assert_eq!(bytes, [1, 2, 3, 4]);
    ///
    /// assert!("!!!".try_from_base64url().is_err()); // invalid chars
    /// # Ok::<(), secure_gate::Base64Error>(())
    /// ```
    fn try_from_base64url(&self) -> Result<Vec<u8>, Base64Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(feature = "encoding-base64")]
impl<T: AsRef<str> + ?Sized> FromBase64UrlStr for T {
    fn try_from_base64url(&self) -> Result<Vec<u8>, Base64Error> {
        URL_SAFE_NO_PAD
            .decode(self.as_ref())
            .map_err(|_| Base64Error::InvalidBase64)
    }
}
