//! # ToBase64Url Trait
//!
//! Extension trait for encoding byte data to URL-safe base64 strings (no padding).
//!
//! This trait provides secure, explicit encoding of byte slices to base64url strings.
//! All methods require the caller to first call `.expose_secret()` (or similar).
//!
//! ## Security Warning
//!
//! These methods produce human-readable strings containing the full secret.
//! Use only when intentionally exposing the secret (e.g., QR codes, user export, audited logging).
//! For debugging/logging, prefer redacted helpers like `to_hex_prefix` from `ToHex`.
//! All calls require explicit `.expose_secret()` first — no implicit paths exist.
//!
/// ## Example
///
/// ```rust
/// use secure_gate::traits::ToBase64Url;
/// let bytes = [0x42u8; 32];
/// let base64_string = bytes.to_base64url();
/// // base64_string is now a URL-safe base64 encoded String
/// ```
#[cfg(feature = "encoding-base64")]
use ::base64 as base64_crate;
#[cfg(feature = "encoding-base64")]
use base64_crate::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "encoding-base64")]
use base64_crate::Engine;

#[cfg(feature = "encoding-base64")]
/// Extension trait for encoding byte data to URL-safe base64 strings (no padding).
///
/// All methods require the caller to first call `.expose_secret()` (or similar).
///
/// # Security Warning
///
/// These methods produce human-readable strings containing the full secret.
/// Use only when intentionally exposing the secret (e.g., QR codes, user export, audited logging).
/// For debugging/logging, prefer redacted helpers like `to_hex_prefix` from `ToHex`.
/// All calls require explicit `.expose_secret()` first — no implicit paths exist.
///
/// # Example
///
/// ```rust
/// use secure_gate::traits::ToBase64Url;
/// let bytes = [0x42u8; 32];
/// let base64_string = bytes.to_base64url();
/// // base64_string is now a URL-safe base64 encoded String
/// ```
pub trait ToBase64Url {
    /// Encode secret bytes as URL-safe base64 (no padding).
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
