#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

#[cfg(feature = "encoding-base64")]
use ::base64 as base64_crate;
#[cfg(feature = "encoding-base64")]
use base64_crate::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "encoding-base64")]
use base64_crate::Engine;

#[cfg(feature = "encoding-bech32")]
use crate::error::Bech32EncodingError;
#[cfg(feature = "encoding-bech32")]
use bech32::{self};

/// Extension trait for safe, explicit encoding of secret byte data to strings.
///
/// All methods require the caller to first call `.expose_secret()` (or similar).
/// This makes every secret access loud, grep-able, and auditable.
///
/// For Bech32 encoding, use the trait methods with an HRP.
///
/// # Security Warning
///
/// These methods produce human-readable strings containing the full secret.
/// Use only when intentionally exposing the secret (e.g., QR codes, user export, audited logging).
/// For debugging/logging, prefer redacted helpers like `to_hex_prefix`.
/// All calls require explicit `.expose_secret()` first — no implicit paths exist.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "encoding-hex")]
/// # {
/// use secure_gate::SecureEncoding;
/// let bytes = [0x42u8; 32];
/// let hex_string = bytes.to_hex();
/// // hex_string is now String: "424242..."
/// # }
/// ```
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub trait SecureEncoding {
    /// Encode secret bytes as lowercase hexadecimal.
    #[cfg(feature = "encoding-hex")]
    fn to_hex(&self) -> alloc::string::String;

    /// Encode secret bytes as uppercase hexadecimal.
    #[cfg(feature = "encoding-hex")]
    fn to_hex_upper(&self) -> alloc::string::String;

    /// Encode secret bytes as lowercase hexadecimal, truncated to `prefix_bytes` with "…" if longer.
    /// Useful for redacted logging or debugging without exposing the full secret.
    #[cfg(feature = "encoding-hex")]
    fn to_hex_prefix(&self, prefix_bytes: usize) -> alloc::string::String {
        let full = self.to_hex();
        if full.len() <= prefix_bytes * 2 {
            full
        } else {
            format!("{}…", &full[..prefix_bytes * 2])
        }
    }

    /// Encode secret bytes as URL-safe base64 (no padding).
    #[cfg(feature = "encoding-base64")]
    fn to_base64url(&self) -> alloc::string::String;

    /// Encode secret bytes as Bech32 with the specified HRP.
    #[cfg(feature = "encoding-bech32")]
    fn to_bech32(&self, hrp: &str) -> alloc::string::String;

    /// Encode secret bytes as Bech32m with the specified HRP.
    #[cfg(feature = "encoding-bech32")]
    fn to_bech32m(&self, hrp: &str) -> alloc::string::String;

    /// Fallibly encode secret bytes as Bech32 with the specified HRP.
    #[cfg(feature = "encoding-bech32")]
    fn try_to_bech32(&self, hrp: &str) -> Result<alloc::string::String, Bech32EncodingError>;

    /// Fallibly encode secret bytes as Bech32m with the specified HRP.
    #[cfg(feature = "encoding-bech32")]
    fn try_to_bech32m(&self, hrp: &str) -> Result<alloc::string::String, Bech32EncodingError>;
}

// Blanket impl to cover any AsRef<[u8]> (e.g., &[u8], Vec<u8>, [u8; N], etc.)
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl<T: AsRef<[u8]> + ?Sized> SecureEncoding for T {
    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex(&self) -> alloc::string::String {
        hex_crate::encode(self.as_ref())
    }

    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        hex_crate::encode_upper(self.as_ref())
    }

    #[cfg(feature = "encoding-hex")]
    fn to_hex_prefix(&self, prefix_bytes: usize) -> alloc::string::String {
        let full = self.as_ref().to_hex();
        if full.len() <= prefix_bytes * 2 {
            full
        } else {
            format!("{}…", &full[..prefix_bytes * 2])
        }
    }

    #[cfg(feature = "encoding-base64")]
    #[inline(always)]
    fn to_base64url(&self) -> alloc::string::String {
        URL_SAFE_NO_PAD.encode(self.as_ref())
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32(&self, hrp: &str) -> alloc::string::String {
        let hrp_parsed = bech32::Hrp::parse(hrp).expect("invalid hrp");
        bech32::encode::<bech32::Bech32>(hrp_parsed, self.as_ref()).expect("bech32 encoding failed")
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
        let hrp_parsed = bech32::Hrp::parse(hrp).expect("invalid hrp");
        bech32::encode::<bech32::Bech32m>(hrp_parsed, self.as_ref())
            .expect("bech32m encoding failed")
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32(&self, hrp: &str) -> Result<alloc::string::String, Bech32EncodingError> {
        let hrp_parsed = bech32::Hrp::parse(hrp).map_err(|_| Bech32EncodingError::InvalidHrp)?;
        bech32::encode::<bech32::Bech32>(hrp_parsed, self.as_ref())
            .map_err(|_| Bech32EncodingError::EncodingFailed)
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32m(&self, hrp: &str) -> Result<alloc::string::String, Bech32EncodingError> {
        let hrp_parsed = bech32::Hrp::parse(hrp).map_err(|_| Bech32EncodingError::InvalidHrp)?;
        bech32::encode::<bech32::Bech32m>(hrp_parsed, self.as_ref())
            .map_err(|_| Bech32EncodingError::EncodingFailed)
    }
}
