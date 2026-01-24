//! # ToHex Trait
//!
//! Extension trait for encoding byte data to lowercase hexadecimal strings.
//!
//! This trait provides secure, explicit encoding of byte slices to hex strings.
//! All methods require the caller to first call `.expose_secret()` (or similar).
//!
//! ## Security Warning
//!
//! These methods produce human-readable strings containing the full secret.
//! Use only when intentionally exposing the secret (e.g., QR codes, user export, audited logging).
//! For debugging/logging, prefer redacted helpers like `to_hex_prefix`.
//! All calls require explicit `.expose_secret()` first — no implicit paths exist.
//!
/// ## Example
///
/// ```rust
/// use secure_gate::traits::ToHex;
/// let bytes = [0x42u8; 32];
/// let hex_string = bytes.to_hex();
/// // hex_string is now String: "424242..."
/// ```
#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

/// Extension trait for encoding byte data to lowercase hexadecimal strings.
///
/// All methods require the caller to first call `.expose_secret()` (or similar).
///
/// # Security Warning
///
/// These methods produce human-readable strings containing the full secret.
/// Use only when intentionally exposing the secret (e.g., QR codes, user export, audited logging).
/// For debugging/logging, prefer redacted helpers like `to_hex_prefix`.
/// All calls require explicit `.expose_secret()` first — no implicit paths exist.
///
/// ## Example
///
/// ```rust
/// use secure_gate::traits::ToHex;
/// let bytes = [0x42u8; 32];
/// let hex_string = bytes.to_hex();
/// // hex_string is now String: "424242..."
/// ```
#[cfg(feature = "encoding-hex")]
pub trait ToHex {
    /// Encode secret bytes as lowercase hexadecimal.
    fn to_hex(&self) -> alloc::string::String;

    /// Encode secret bytes as uppercase hexadecimal.
    fn to_hex_upper(&self) -> alloc::string::String;

    /// Encode secret bytes as lowercase hexadecimal, truncated to `prefix_bytes` with "…" if longer.
    /// Useful for redacted logging or debugging without exposing the full secret.
    fn to_hex_prefix(&self, prefix_bytes: usize) -> alloc::string::String {
        let full = self.to_hex();
        if full.len() <= prefix_bytes * 2 {
            full
        } else {
            format!("{}…", &full[..prefix_bytes * 2])
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
