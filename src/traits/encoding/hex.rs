//! Hexadecimal encoding trait.
//!
//! This trait provides secure, explicit encoding of byte data to lowercase
//! (or uppercase) hexadecimal strings. It is intended for intentional export
//! only (QR codes, audited logs, API responses).
//!
//! Requires the `encoding-hex` feature.
//!
//! # Security Notes
//! - **Full secret exposure**: The resulting string contains the **entire** secret.
//!   Use only after explicit `.expose_secret()`.
//! - **Redacted helper**: `to_hex_left` is provided for safe partial display in logs.
//! - **Scoped access enforced**: No implicit exposure paths exist.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-hex")]
//! use secure_gate::{Fixed, ToHex, ExposeSecret};
//!
//! # #[cfg(feature = "encoding-hex")]
//! {
//! let secret = Fixed::new([0x42u8; 4]);
//! let hex = secret.expose_secret().to_hex();
//! assert_eq!(hex, "42424242");
//!
//! let hex_upper = secret.expose_secret().to_hex_upper();
//! assert_eq!(hex_upper, "42424242");
//!
//! // Redacted for logs
//! let redacted = secret.expose_secret().to_hex_left(2);
//! assert_eq!(redacted, "42…");
//! # }
//! ```
#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

/// Extension trait for encoding byte data to hexadecimal strings.
///
/// Requires `encoding-hex` feature.
///
/// All methods require explicit `.expose_secret()` access first.
#[cfg(feature = "encoding-hex")]
pub trait ToHex {
    /// Encode bytes as lowercase hexadecimal.
    fn to_hex(&self) -> alloc::string::String;

    /// Encode bytes as uppercase hexadecimal.
    fn to_hex_upper(&self) -> alloc::string::String;

    /// Encode bytes as lowercase hexadecimal, truncated to the first `bytes` with '…' if longer.
    ///
    /// Useful for redacted logging/debugging without exposing the full secret.
    fn to_hex_left(&self, bytes: usize) -> alloc::string::String {
        let full = self.to_hex();
        if full.len() <= bytes * 2 {
            full
        } else {
            format!("{}…", &full[..bytes * 2])
        }
    }
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
