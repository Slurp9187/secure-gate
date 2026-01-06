#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

#[cfg(feature = "encoding-base64")]
use ::base64 as base64_crate;
#[cfg(feature = "encoding-base64")]
use base64_crate::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "encoding-base64")]
use base64_crate::Engine;

#[cfg(feature = "encoding-bech32")]
use ::bech32::{self, Bech32, Bech32m, Hrp};

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
/// # #[cfg(feature = "encoding")]
/// # {
/// # use secure_gate::{fixed_alias, encoding::SecureEncodingExt};
/// # fixed_alias!(Aes256Key, 32);
/// # let key = Aes256Key::from([0x42u8; 32]);
/// # let hex = key.expose_secret().to_hex();         // → "424242..."
/// # let b64 = key.expose_secret().to_base64url();   // URL-safe, no padding
/// # let b32 = key.expose_secret().to_bech32("example"); // Bech32 with HRP
/// # assert_eq!(hex, "4242424242424242424242424242424242424242424242424242424242424242");
/// # }
/// ```
// Trait is available when any encoding feature is enabled
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub trait SecureEncodingExt {
    /// Encode secret bytes as lowercase hexadecimal.
    #[cfg(feature = "encoding-hex")]
    fn to_hex(&self) -> alloc::string::String;

    /// Encode secret bytes as uppercase hexadecimal.
    #[cfg(feature = "encoding-hex")]
    fn to_hex_upper(&self) -> alloc::string::String;

    /// Encode secret bytes as URL-safe base64 (no padding).
    #[cfg(feature = "encoding-base64")]
    fn to_base64url(&self) -> alloc::string::String;

    /// Encode secret bytes as Bech32 with the specified HRP.
    #[cfg(feature = "encoding-bech32")]
    fn to_bech32(&self, hrp: &str) -> crate::encoding::bech32::Bech32String;

    /// Encode secret bytes as Bech32m with the specified HRP.
    #[cfg(feature = "encoding-bech32")]
    fn to_bech32m(&self, hrp: &str) -> crate::encoding::bech32::Bech32String;
}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl SecureEncodingExt for [u8] {
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
    #[cfg(feature = "encoding-base64")]
    #[inline(always)]
    fn to_base64url(&self) -> alloc::string::String {
        URL_SAFE_NO_PAD.encode(self)
    }
    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = bech32::Hrp::parse(hrp).expect("invalid HRP");
        let encoded =
            bech32::encode::<bech32::Bech32>(hrp, self).expect("encoding valid bytes cannot fail");

        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        )
    }
    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32m(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = bech32::Hrp::parse(hrp).expect("invalid HRP");
        let encoded =
            bech32::encode::<bech32::Bech32m>(hrp, self).expect("encoding valid bytes cannot fail");

        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        )
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
    fn to_hex(&self) -> alloc::string::String {
        hex_crate::encode(self)
    }

    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        hex_crate::encode_upper(self)
    }

    #[cfg(feature = "encoding-base64")]
    #[inline(always)]
    fn to_base64url(&self) -> alloc::string::String {
        URL_SAFE_NO_PAD.encode(self)
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = bech32::Hrp::parse(hrp).expect("invalid HRP");
        let encoded =
            bech32::encode::<bech32::Bech32>(hrp, self).expect("encoding valid bytes cannot fail");

        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        )
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32m(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = bech32::Hrp::parse(hrp).expect("invalid HRP");
        let encoded =
            bech32::encode::<bech32::Bech32m>(hrp, self).expect("encoding valid bytes cannot fail");

        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        )
    }
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
impl crate::DynamicRng {
    /// Consume self and return the random bytes as a validated Bech32 string with the specified HRP.
    ///
    /// The raw bytes are zeroized immediately after encoding (via drop of `self`).
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid or encoding fails (should never happen for valid random bytes).
    pub fn into_bech32(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = bech32::encode::<Bech32>(hrp, self.expose_secret())
            .expect("encoding valid random bytes cannot fail");

        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        )
    }

    /// Consume self and return the random bytes as a validated Bech32m string with the specified HRP.
    ///
    /// The raw bytes are zeroized immediately after encoding (via drop of `self`).
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid or encoding fails (should never happen for valid random bytes).
    pub fn into_bech32m(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = bech32::encode::<Bech32m>(hrp, self.expose_secret())
            .expect("encoding valid random bytes cannot fail");

        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        )
    }
}

#[cfg(all(feature = "rand", feature = "encoding-hex"))]
impl crate::DynamicRng {
    /// Consume self and return the random bytes as a validated hex string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    pub fn into_hex(self) -> crate::encoding::hex::HexString {
        let hex_str = hex_crate::encode(self.expose_secret());
        crate::encoding::hex::HexString::new_unchecked(hex_str)
    }
}

#[cfg(all(feature = "rand", feature = "encoding-base64"))]
impl crate::DynamicRng {
    /// Consume self and return the random bytes as a validated base64 string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    pub fn into_base64(self) -> crate::encoding::base64::Base64String {
        let encoded = URL_SAFE_NO_PAD.encode(self.expose_secret());
        crate::encoding::base64::Base64String::new_unchecked(encoded)
    }
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
impl<const N: usize> crate::FixedRng<N> {
    /// Consume self and return the random bytes as a validated Bech32 string with the specified HRP.
    ///
    /// The raw bytes are zeroized immediately after encoding (via drop of `self`).
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid or encoding fails (should never happen for valid random bytes).
    pub fn into_bech32(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = bech32::encode::<Bech32>(hrp, self.expose_secret())
            .expect("encoding valid random bytes cannot fail");

        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        )
    }

    /// Consume self and return the random bytes as a validated Bech32m string with the specified HRP.
    ///
    /// The raw bytes are zeroized immediately after encoding (via drop of `self`).
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid or encoding fails (should never happen for valid random bytes).
    pub fn into_bech32m(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = bech32::encode::<Bech32m>(hrp, self.expose_secret())
            .expect("encoding valid random bytes cannot fail");

        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        )
    }
}

#[cfg(all(feature = "rand", feature = "encoding-hex"))]
impl<const N: usize> crate::FixedRng<N> {
    /// Consume self and return the random bytes as a validated hex string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    pub fn into_hex(self) -> crate::encoding::hex::HexString {
        let hex_str = hex_crate::encode(self.expose_secret());
        crate::encoding::hex::HexString::new_unchecked(hex_str)
    }
}

#[cfg(all(feature = "rand", feature = "encoding-base64"))]
impl<const N: usize> crate::FixedRng<N> {
    /// Consume self and return the random bytes as a validated base64 string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    pub fn into_base64(self) -> crate::encoding::base64::Base64String {
        let encoded = URL_SAFE_NO_PAD.encode(self.expose_secret());
        crate::encoding::base64::Base64String::new_unchecked(encoded)
    }
}

/// View struct for exposed hex strings, allowing decoding without direct access.
#[cfg(feature = "encoding-hex")]
pub struct HexStringView<'a>(pub(crate) &'a String);

#[cfg(feature = "encoding-hex")]
impl<'a> HexStringView<'a> {
    /// Decode the validated hex string into raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        hex_crate::decode(self.0).expect("HexString is always valid")
    }
}

/// View struct for exposed base64 strings, allowing decoding without direct access.
#[cfg(feature = "encoding-base64")]
pub struct Base64StringView<'a>(pub(crate) &'a String);

#[cfg(feature = "encoding-base64")]
impl<'a> Base64StringView<'a> {
    /// Decode the validated base64 string into raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(self.0)
            .expect("Base64String is always valid")
    }
}

/// View struct for exposed Bech32 strings, allowing decoding without direct access.
#[cfg(feature = "encoding-bech32")]
pub struct Bech32StringView<'a>(pub(crate) &'a String);

#[cfg(feature = "encoding-bech32")]
impl<'a> Bech32StringView<'a> {
    /// Decode the validated Bech32 string into raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let (_, data) = bech32::decode(self.0).expect("Bech32String is always valid");
        data
    }
}

#[cfg(feature = "encoding-hex")]
impl<'a> core::ops::Deref for HexStringView<'a> {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[cfg(feature = "encoding-base64")]
impl<'a> core::ops::Deref for Base64StringView<'a> {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[cfg(feature = "encoding-bech32")]
impl<'a> core::ops::Deref for Bech32StringView<'a> {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

// Impl expose_secret for HexString to return view
#[cfg(feature = "encoding-hex")]
impl crate::encoding::hex::HexString {
    pub fn expose_secret(&'_ self) -> HexStringView<'_> {
        HexStringView(self.0.expose_secret())
    }
}

// Impl expose_secret for Base64String to return view
#[cfg(feature = "encoding-base64")]
impl crate::encoding::base64::Base64String {
    pub fn expose_secret(&'_ self) -> Base64StringView<'_> {
        Base64StringView(self.0.expose_secret())
    }
}

// Impl expose_secret for Bech32String to return view
#[cfg(feature = "encoding-bech32")]
impl crate::encoding::bech32::Bech32String {
    pub fn expose_secret(&self) -> Bech32StringView<'_> {
        Bech32StringView(self.inner.expose_secret())
    }
}

// Consuming decode variants for secure zeroization of encoded forms

#[cfg(feature = "encoding-hex")]
impl crate::encoding::hex::HexString {
    /// Decode the validated hex string into raw bytes, consuming and zeroizing the wrapper.
    pub fn into_bytes(self) -> Vec<u8> {
        hex_crate::decode(&*self.expose_secret()).expect("HexString is always valid")
    }
}

#[cfg(feature = "encoding-base64")]
impl crate::encoding::base64::Base64String {
    /// Decode the validated base64 string into raw bytes, consuming and zeroizing the wrapper.
    pub fn into_bytes(self) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(&*self.expose_secret())
            .expect("Base64String is always valid")
    }
}

#[cfg(feature = "encoding-bech32")]
impl crate::encoding::bech32::Bech32String {
    /// Decode the validated Bech32 string into raw bytes, consuming and zeroizing the wrapper.
    pub fn into_bytes(self) -> Vec<u8> {
        let (_, data) =
            bech32::decode(&self.expose_secret()).expect("Bech32String is always valid");
        data
    }
}
