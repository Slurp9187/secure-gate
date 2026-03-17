//! URL-safe Base64 encoding trait.
//!
//! This trait provides secure, explicit encoding of byte data to URL-safe
//! base64 strings (no padding, RFC 4648). It is intended for intentional
//! export scenarios only (QR codes, API responses, audited logging).
//!
//! Requires the `encoding-base64` feature.
//!
//! # Security Notes
//! - **Full secret exposure**: The resulting string contains the **entire** secret.
//!   Use only after explicit `.expose_secret()` and only when the exposure is
//!   deliberate and protected (encryption, short-lived, etc.).
//! - **No implicit paths**: You **must** call `.expose_secret()` (or equivalent)
//!   first — no `Deref` or automatic conversion exists.
//! - **URL-safe**: No padding (`=`), safe for URLs/JSON/filenames.
//! - **Redacted alternatives**: For logging/debugging use `to_hex_left` (from `ToHex`).
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-base64")]
//! use secure_gate::{Fixed, ToBase64Url, ExposeSecret};
//! # #[cfg(feature = "encoding-base64")]
//! {
//! let secret = Fixed::new([0x42u8; 4]);
//!
//! // Blanket impl on the inner byte array (via with_secret):
//! let b64 = secret.with_secret(|s| s.to_base64url());
//! assert_eq!(b64, "QkJCQg");
//!
//! // Wrapper method (Direct Fixed<[u8; N]> API — same result):
//! assert_eq!(secret.to_base64url(), "QkJCQg");
//! }
//! ```
#[cfg(feature = "encoding-base64")]
use ::base64 as base64_crate;

#[cfg(feature = "encoding-base64")]
use base64_crate::engine::general_purpose::URL_SAFE_NO_PAD;

#[cfg(feature = "encoding-base64")]
use base64_crate::Engine;

/// Extension trait for encoding byte data as URL-safe base64 strings (no padding).
///
/// *Requires feature `encoding-base64`.*
///
/// Blanket-implemented for all `AsRef<[u8]>` types. Uses the RFC 4648 URL-safe
/// alphabet without `=` padding. To encode a secret wrapper, access inner bytes
/// via `with_secret` first, or call the wrapper's inherent `to_base64url()` method.
#[cfg(feature = "encoding-base64")]
pub trait ToBase64Url {
    /// Encode bytes as URL-safe base64 (no padding).
    fn to_base64url(&self) -> alloc::string::String;
}

// Blanket impl to cover any AsRef<[u8]> (e.g., &[u8], Vec<u8>, [u8; N], etc.)
#[cfg(feature = "encoding-base64")]
impl<T: AsRef<[u8]> + ?Sized> ToBase64Url for T {
    #[inline(always)]
    fn to_base64url(&self) -> alloc::string::String {
        URL_SAFE_NO_PAD.encode(self.as_ref())
    }
}
