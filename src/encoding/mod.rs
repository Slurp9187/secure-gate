// ==========================================================================
// src/encoding/mod.rs
// ==========================================================================

// Allow unsafe_code when zeroize is enabled (not needed here, but consistent)
// but forbid it when neither encoding feature is enabled
#![cfg_attr(
    not(any(feature = "encoding-hex", feature = "encoding-base64")),
    forbid(unsafe_code)
)]

#[cfg(feature = "encoding-hex")]
pub mod hex;

#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

#[cfg(feature = "encoding-base64")]
pub mod base64;



/// Extension trait for safe, explicit encoding of secret byte data to strings.
///
/// All methods require the caller to first call `.expose_secret()` (or similar).
/// This makes every secret access loud, grep-able, and auditable.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "conversions")]
/// # {
/// # use secure_gate::{fixed_alias, encoding::SecureConversionsExt};
/// # fixed_alias!(Aes256Key, 32);
/// # let key = Aes256Key::from([0x42u8; 32]);
/// # let hex = key.expose_secret().to_hex();         // → "424242..."
/// # let b64 = key.expose_secret().to_base64url();   // URL-safe, no padding
/// # assert_eq!(hex, "4242424242424242424242424242424242424242424242424242424242424242");
/// # }
/// ```
// Trait is available when any encoding feature is enabled
#[cfg(any(feature = "encoding-hex", feature = "encoding-base64"))]
pub trait SecureConversionsExt {
    /// Encode secret bytes as lowercase hexadecimal.
    #[cfg(feature = "encoding-hex")]
    fn to_hex(&self) -> alloc::string::String;

    /// Encode secret bytes as uppercase hexadecimal.
    #[cfg(feature = "encoding-hex")]
    fn to_hex_upper(&self) -> alloc::string::String;
}

#[cfg(feature = "encoding-hex")]
impl SecureConversionsExt for [u8] {
    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex(&self) -> alloc::string::String {
        hex_crate::encode(self)
    }
    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        hex_crate::encode_upper(self)
    }
}

#[cfg(feature = "encoding-hex")]
impl<const N: usize> SecureConversionsExt for [u8; N] {
    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex(&self) -> alloc::string::String {
        hex_crate::encode(self)
    }

    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        hex_crate::encode_upper(self)
    }
}
