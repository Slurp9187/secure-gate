// secure-gate/src/traits/decoding/base64_url.rs
//! # FromBase64UrlStr Trait
//!
//! Extension trait for decoding URL-safe base64 strings to byte data.
//!
//! This trait provides secure, explicit decoding of base64url strings to byte vectors.
//! Input should be treated as untrusted; use fallible methods.
//!
//! ## Security Warning
//!
//! Decoding input from untrusted sources should use fallible `try_` methods.
//! Invalid input may indicate tampering or errors.
//!
/// ## Example
///
/// ```rust
/// use secure_gate::traits::FromBase64UrlStr;
/// let base64_string = "QkJC";
/// let bytes = base64_string.try_from_base64url().unwrap();
/// // bytes is now Vec<u8>: [66, 66, 66]
/// ```
/// This trait is gated behind the `encoding-base64` feature.
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
/// Input should be treated as untrusted; use fallible methods.
///
/// # Security Warning
///
/// Decoding input from untrusted sources should use fallible `try_` methods.
/// Invalid input may indicate tampering or errors.
///
/// ## Example
///
/// ```rust
/// use secure_gate::traits::FromBase64UrlStr;
/// let base64_string = "QkJC";
/// let bytes = base64_string.try_from_base64url().unwrap();
/// // bytes is now Vec<u8>: [66, 66, 66]
/// ```
#[cfg(feature = "encoding-base64")]
pub trait FromBase64UrlStr {
    /// Fallibly decode a URL-safe base64 string to bytes.
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
