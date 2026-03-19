//! Hexadecimal encoding trait.
//!
//! This trait provides secure, explicit encoding of byte data to lowercase
//! (or uppercase) hexadecimal strings. It is intended for intentional export
//! only (QR codes, audited logs, API responses).
//!
//! Requires the `encoding-hex` feature.
//!
//! # Security Notes
//!
//! - **Full secret exposure**: The resulting string contains the **entire** secret.
//!   Always treat output as sensitive; do not log or persist without protection.
//! - **Treat all input as untrusted**: validate hex strings upstream before wrapping
//!   in secrets.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-hex")]
//! use secure_gate::{Fixed, ToHex, ExposeSecret};
//! # #[cfg(feature = "encoding-hex")]
//! {
//! let secret = Fixed::new([0x0au8, 0x0bu8, 0x0cu8, 0x0du8]);
//!
//! // Blanket impl on the inner byte array (via with_secret):
//! let hex = secret.with_secret(|s| s.to_hex());
//! assert_eq!(hex, "0a0b0c0d");
//!
//! let hex_upper = secret.with_secret(|s| s.to_hex_upper());
//! assert_eq!(hex_upper, "0A0B0C0D");
//!
//! // Wrapper method (Direct Fixed<[u8; N]> API — same result):
//! assert_eq!(secret.to_hex(), "0a0b0c0d");
//! }
//! ```
#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

/// Extension trait for encoding byte data as hexadecimal strings.
///
/// *Requires feature `encoding-hex`.*
///
/// Blanket-implemented for all `AsRef<[u8]>` types (byte slices, arrays, `Vec<u8>`).
/// To encode a secret wrapper, access the inner bytes via `with_secret` first, or
/// call the wrapper's inherent `to_hex()` method if available.
#[cfg(feature = "encoding-hex")]
pub trait ToHex {
    /// Encode bytes as lowercase hexadecimal.
    fn to_hex(&self) -> alloc::string::String;

    /// Encode bytes as uppercase hexadecimal.
    fn to_hex_upper(&self) -> alloc::string::String;

}

// Blanket impl to cover any AsRef<[u8]> (e.g., &[u8], Vec<u8>, [u8; N], etc.)
#[cfg(feature = "encoding-hex")]
impl<T: AsRef<[u8]> + ?Sized> ToHex for T {
    #[inline(always)]
    fn to_hex(&self) -> alloc::string::String {
        hex_crate::encode(self.as_ref())
    }

    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        hex_crate::encode_upper(self.as_ref())
    }
}
