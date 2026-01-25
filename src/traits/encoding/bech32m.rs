#[cfg(feature = "encoding-bech32")]
use ::bech32;

#[cfg(feature = "encoding-bech32")]
use crate::error::Bech32Error;
#[cfg(feature = "encoding-bech32")]
use crate::utilities::conversion::convert_bits;

/// Extension trait for encoding byte data to Bech32m strings with a specified Human-Readable Part (HRP).
///
/// All methods require the caller to first call `.expose_secret()` (or similar).
///
/// # Bech32m Feature Note
///
/// Currently shares implementation with Bech32; reserved for future strict variant enforcement.
///
/// # Security Warning
///
/// These methods produce human-readable strings containing the full secret.
/// Use only when intentionally exposing the secret (e.g., QR codes, user export, audited logging).
/// For debugging/logging, prefer redacted helpers like `to_hex_left` from `ToHex`.
/// All calls require explicit `.expose_secret()` first — no implicit paths exist.
///
/// Decoding input from untrusted sources should use fallible `try_` methods.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "encoding-bech32")]
/// use secure_gate::ToBech32m;
/// # #[cfg(feature = "encoding-bech32")]
/// let bytes = [0x42u8; 20];
/// # #[cfg(feature = "encoding-bech32")]
/// let bech32m_string = bytes.to_bech32m("bc");
/// // bech32m_string is now a Bech32m encoded String with "bc" HRP
/// ```
#[cfg(feature = "encoding-bech32")]
pub trait ToBech32m {
    /// Encode secret bytes as Bech32m with the specified HRP.
    fn to_bech32m(&self, hrp: &str) -> alloc::string::String;

    /// Fallibly encode secret bytes as Bech32m with the specified HRP and optional expected HRP validation.
    fn try_to_bech32m(
        &self,
        hrp: &str,
        expected_hrp: Option<&str>,
    ) -> Result<alloc::string::String, Bech32Error>;
}

// Blanket impl to cover any AsRef<[u8]> (e.g., &[u8], Vec<u8>, [u8; N], etc.)
#[cfg(feature = "encoding-bech32")]
impl<T: AsRef<[u8]> + ?Sized> ToBech32m for T {
    #[inline(always)]
    fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
        let (converted, _) =
            convert_bits(8, 5, true, self.as_ref()).expect("bech32 bit conversion failed");
        let hrp_parsed = bech32::Hrp::parse(hrp).expect("invalid hrp");
        bech32::encode::<bech32::Bech32m>(hrp_parsed, &converted).expect("bech32m encoding failed")
    }

    #[inline(always)]
    fn try_to_bech32m(
        &self,
        hrp: &str,
        expected_hrp: Option<&str>,
    ) -> Result<alloc::string::String, Bech32Error> {
        let (converted, _) =
            convert_bits(8, 5, true, self.as_ref()).map_err(|_| Bech32Error::ConversionFailed)?;
        let hrp_parsed = bech32::Hrp::parse(hrp).map_err(|_| Bech32Error::InvalidHrp)?;
        if let Some(exp) = expected_hrp {
            if hrp != exp {
                return Err(Bech32Error::UnexpectedHrp {
                    expected: exp.to_string(),
                    got: hrp.to_string(),
                });
            }
        }
        bech32::encode::<bech32::Bech32m>(hrp_parsed, &converted)
            .map_err(|_| Bech32Error::OperationFailed)
    }
}
