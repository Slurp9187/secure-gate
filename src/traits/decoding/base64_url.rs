//! URL-safe Base64 decoding trait.
//!
//! This trait provides secure, explicit decoding of base64url-encoded strings
//! (URL-safe alphabet, no padding) to byte vectors. It is designed for handling
//! untrusted input in cryptographic contexts, such as decoding encoded keys or tokens.
//!
//! Requires the `encoding-base64` feature.
//!
//! # Security Notes
//! - **Untrusted input**: Always treat decoded data as potentially malicious.
//!   Use fallible methods and validate lengths/content after decoding.
//! - **Invalid input**: May indicate tampering, injection attempts, or errors —
//!   log/handle carefully without leaking details.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in `Fixed` or `Dynamic` for secrets.
//! - **No auto-padding**: Strict base64url (no '=' padding) per RFC 4648.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-base64")]
//! use secure_gate::FromBase64UrlStr;
//!
//! # #[cfg(feature = "encoding-base64")]
//! {
//! let b64 = "AQIDBA";
//! let bytes = b64.try_from_base64url().unwrap();
//! assert_eq!(bytes, vec![1, 2, 3, 4]);
//! # }
//! ```
#[cfg(feature = "encoding-base64")]
use ::base64 as base64_crate;

#[cfg(feature = "encoding-base64")]
use base64_crate::engine::general_purpose::URL_SAFE_NO_PAD;

#[cfg(feature = "encoding-base64")]
use base64_crate::Engine;

#[cfg(feature = "encoding-base64")]
use crate::error::Base64Error;

/// Extension trait for decoding URL-safe base64 strings to byte data.
///
/// Requires `encoding-base64` feature.
///
/// # Security Warning
///
/// Treat all input as untrusted — invalid base64 may indicate tampering.
/// Always use the fallible `try_from_base64url` and handle errors securely.
#[cfg(feature = "encoding-base64")]
pub trait FromBase64UrlStr {
    /// Fallibly decodes a URL-safe base64 string to bytes.
    ///
    /// Returns [`Base64Error::InvalidBase64`] for invalid characters or padding.
    /// Requires `encoding-base64` feature.
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
