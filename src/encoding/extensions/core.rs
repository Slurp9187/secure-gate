#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

#[cfg(feature = "encoding-base64")]
use ::base64 as base64_crate;
#[cfg(feature = "encoding-base64")]
use base64_crate::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "encoding-base64")]
use base64_crate::Engine;

#[cfg(feature = "encoding-bech32")]
use ::bech32::{self};

/// Extension trait for safe, explicit encoding of secret byte data to strings.
///
/// All methods require the caller to first call `.expose_secret()` (or similar).
/// This makes every secret access loud, grep-able, and auditable.
///
/// For Bech32 encoding, use the trait methods with an HRP.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "encoding-hex")]
/// # {
/// use secure_gate::SecureEncodingExt;
/// let bytes = [0x42u8; 32];
/// let hex_string = bytes.to_hex();
/// let hex = hex_string.expose_secret(); // → "424242..."
/// # }
/// ```
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub trait SecureEncodingExt {
    /// Encode secret bytes as lowercase hexadecimal.
    #[cfg(feature = "encoding-hex")]
    fn to_hex(&self) -> crate::encoding::hex::HexString;

    /// Encode secret bytes as uppercase hexadecimal.
    #[cfg(feature = "encoding-hex")]
    fn to_hex_upper(&self) -> alloc::string::String;

    /// Encode secret bytes as URL-safe base64 (no padding).
    #[cfg(feature = "encoding-base64")]
    fn to_base64url(&self) -> crate::encoding::base64::Base64String;

    /// Try to encode secret bytes as Bech32 with the specified HRP.
    #[cfg(feature = "encoding-bech32")]
    fn try_to_bech32(
        &self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, &'static str>;

    /// Try to encode secret bytes as Bech32m with the specified HRP.
    #[cfg(feature = "encoding-bech32")]
    fn try_to_bech32m(
        &self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, &'static str>;
}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl SecureEncodingExt for [u8] {
    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex(&self) -> crate::encoding::hex::HexString {
        crate::encoding::hex::HexString::new_unchecked(hex_crate::encode(self))
    }

    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        hex_crate::encode_upper(self)
    }

    #[cfg(feature = "encoding-base64")]
    #[inline(always)]
    fn to_base64url(&self) -> crate::encoding::base64::Base64String {
        crate::encoding::base64::Base64String::new_unchecked(URL_SAFE_NO_PAD.encode(self))
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32(
        &self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, &'static str> {
        let hrp = bech32::Hrp::parse(hrp).map_err(|_| "invalid HRP")?;
        let encoded = bech32::encode::<bech32::Bech32>(hrp, self).map_err(|_| "encoding failed")?;
        Ok(crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        ))
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32m(
        &self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, &'static str> {
        let hrp = bech32::Hrp::parse(hrp).map_err(|_| "invalid HRP")?;
        let encoded =
            bech32::encode::<bech32::Bech32m>(hrp, self).map_err(|_| "encoding failed")?;
        Ok(crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        ))
    }
}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl<const N: usize> SecureEncodingExt for [u8; N] {
    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex(&self) -> crate::encoding::hex::HexString {
        crate::encoding::hex::HexString::new_unchecked(hex_crate::encode(self))
    }

    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        hex_crate::encode_upper(self)
    }

    #[cfg(feature = "encoding-base64")]
    #[inline(always)]
    fn to_base64url(&self) -> crate::encoding::base64::Base64String {
        crate::encoding::base64::Base64String::new_unchecked(URL_SAFE_NO_PAD.encode(self))
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32(
        &self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, &'static str> {
        let hrp = bech32::Hrp::parse(hrp).map_err(|_| "invalid HRP")?;
        let encoded = bech32::encode::<bech32::Bech32>(hrp, self).map_err(|_| "encoding failed")?;
        Ok(crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        ))
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32m(
        &self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, &'static str> {
        let hrp = bech32::Hrp::parse(hrp).map_err(|_| "invalid HRP")?;
        let encoded =
            bech32::encode::<bech32::Bech32m>(hrp, self).map_err(|_| "encoding failed")?;
        Ok(crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        ))
    }
}
