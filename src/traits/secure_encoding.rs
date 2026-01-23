#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

#[cfg(feature = "encoding-base64")]
use ::base64 as base64_crate;
#[cfg(feature = "encoding-base64")]
use base64_crate::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "encoding-base64")]
use base64_crate::Engine;

#[cfg(feature = "encoding-bech32")]
use crate::error::Bech32Error;

/// Local implementation of bit conversion for Bech32, since bech32 crate doesn't expose it in v0.11.
#[cfg(feature = "encoding-bech32")]
fn convert_bits(
    from: u8,
    to: u8,
    pad: bool,
    data: &[u8],
) -> Result<(alloc::vec::Vec<u8>, usize), ()> {
    if !(1..=8).contains(&from) || !(1..=8).contains(&to) {
        return Err(());
    }
    let mut acc = 0u64;
    let mut bits = 0u8;
    let mut ret = alloc::vec::Vec::new();
    let maxv = (1u64 << to) - 1;
    let _max_acc = (1u64 << (from + to - 1)) - 1;
    for &v in data {
        if ((v as u32) >> from) != 0 {
            return Err(());
        }
        acc = (acc << from) | (v as u64);
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(());
    }
    Ok((ret, bits as usize))
}

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

    /// Fallibly encode secret bytes as Bech32 with the specified HRP and optional expected HRP validation.
    #[cfg(feature = "encoding-bech32")]
    fn try_to_bech32(
        &self,
        hrp: &str,
        expected_hrp: Option<&str>,
    ) -> Result<alloc::string::String, Bech32Error>;

    /// Fallibly encode secret bytes as Bech32m with the specified HRP and optional expected HRP validation.
    #[cfg(feature = "encoding-bech32")]
    fn try_to_bech32m(
        &self,
        hrp: &str,
        expected_hrp: Option<&str>,
    ) -> Result<alloc::string::String, Bech32Error>;
}

// Blanket impl to cover any AsRef<[u8]> (e.g., &[u8], Vec<u8>, [u8; N], etc.)
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
        let (converted, _) =
            convert_bits(8, 5, true, self.as_ref()).expect("bech32 bit conversion failed");
        let hrp_parsed = bech32::Hrp::parse(hrp).expect("invalid hrp");
        bech32::encode::<bech32::Bech32>(hrp_parsed, &converted).expect("bech32 encoding failed")
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
        let (converted, _) =
            convert_bits(8, 5, true, self.as_ref()).expect("bech32 bit conversion failed");
        let hrp_parsed = bech32::Hrp::parse(hrp).expect("invalid hrp");
        bech32::encode::<bech32::Bech32m>(hrp_parsed, &converted).expect("bech32m encoding failed")
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32(
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
        bech32::encode::<bech32::Bech32>(hrp_parsed, &converted)
            .map_err(|_| Bech32Error::OperationFailed)
    }

    #[cfg(feature = "encoding-bech32")]
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
