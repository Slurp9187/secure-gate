// secure-gate/src/random/dynamic_rng.rs

use crate::Dynamic;
use rand::rand_core::OsError;
use rand::rngs::OsRng;
use rand::TryRngCore;

/// Heap-allocated cryptographically secure random bytes with encoding methods.
///
/// This is a newtype over `Dynamic<Vec<u8>>` for semantic clarity.
/// Like `FixedRng`, guarantees freshness via RNG construction.
///
/// Requires the "rand" feature.
///
/// Supports direct encoding to Hex, Base64, Bech32, and Bech32m via convenience methods.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::random::DynamicRng;
/// let random = DynamicRng::generate(64);
/// assert_eq!(random.len(), 64);
/// # }
/// ```
pub struct DynamicRng(Dynamic<Vec<u8>>);

impl DynamicRng {
    /// Generate fresh random bytes of the specified length.
    ///
    /// Panics if the RNG fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let random = DynamicRng::generate(128);
    /// # }
    /// ```
    pub fn generate(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failed — this should never happen on supported platforms");
        Self(Dynamic::from(bytes))
    }

    /// Try to generate fresh random bytes of the specified length.
    ///
    /// Returns an error if the RNG fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let random: Result<DynamicRng, rand::rand_core::OsError> = DynamicRng::try_generate(64);
    /// assert!(random.is_ok());
    /// # }
    /// ```
    pub fn try_generate(len: usize) -> Result<Self, OsError> {
        let mut bytes = vec![0u8; len];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map(|_| Self(Dynamic::from(bytes)))
    }

    /// Expose the random bytes for read-only access.
    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Returns the length in bytes.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if empty.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume and return the inner `Dynamic<Vec<u8>>`.
    #[inline(always)]
    pub fn into_inner(self) -> Dynamic<Vec<u8>> {
        self.0
    }
}

impl core::fmt::Debug for DynamicRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
impl DynamicRng {
    /// Consume self and return the random bytes as a validated Bech32 string with the specified HRP.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    ///
    /// # Panics
    ///
    /// Panics if encoding fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "encoding-bech32"))]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let bech32 = DynamicRng::generate(16).into_bech32("test");
    /// println!("random bech32: {}", bech32.expose_secret());
    /// # }
    /// ```
    pub fn into_bech32(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        use bech32::{Bech32, Hrp};
        let hrp = Hrp::parse(hrp).unwrap();
        let data = crate::encoding::bech32::convert_bits(self.expose_secret(), 8, 5, true).unwrap();
        let encoded = bech32::encode::<Bech32>(hrp, &data).expect("encoding failed");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        )
    }

    /// Encode to Bech32 without consuming self, for cases where raw is still needed briefly.
    ///
    /// # Panics
    ///
    /// Panics if encoding fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "encoding-bech32"))]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let rng = DynamicRng::generate(16);
    /// let bech32 = rng.to_bech32("test");
    /// // Use rng for something else here
    /// # }
    /// ```
    pub fn to_bech32(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        use bech32::{Bech32, Hrp};
        let hrp = Hrp::parse(hrp).unwrap();
        let data = crate::encoding::bech32::convert_bits(self.expose_secret(), 8, 5, true).unwrap();
        let encoded = bech32::encode::<Bech32>(hrp, &data).expect("encoding failed");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        )
    }

    /// Consume self and return the random bytes as a validated Bech32m string with the specified HRP.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    ///
    /// # Panics
    ///
    /// Panics if encoding fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "encoding-bech32"))]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let bech32m = DynamicRng::generate(16).into_bech32m("test");
    /// println!("random bech32m: {}", bech32m.expose_secret());
    /// # }
    /// ```
    pub fn into_bech32m(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        use bech32::{Bech32m, Hrp};
        let hrp = Hrp::parse(hrp).unwrap();
        let data = crate::encoding::bech32::convert_bits(self.expose_secret(), 8, 5, true).unwrap();
        let encoded = bech32::encode::<Bech32m>(hrp, &data).expect("encoding failed");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        )
    }

    /// Encode to Bech32m without consuming self, for cases where raw is still needed briefly.
    ///
    /// # Panics
    ///
    /// Panics if encoding fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "encoding-bech32"))]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let rng = DynamicRng::generate(16);
    /// let bech32m = rng.to_bech32m("test");
    /// // Use rng for something else here
    /// # }
    /// ```
    pub fn to_bech32m(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        use bech32::{Bech32m, Hrp};
        let hrp = Hrp::parse(hrp).unwrap();
        let data = crate::encoding::bech32::convert_bits(self.expose_secret(), 8, 5, true).unwrap();
        let encoded = bech32::encode::<Bech32m>(hrp, &data).expect("encoding failed");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        )
    }
}

#[cfg(all(feature = "rand", feature = "encoding-hex"))]
impl DynamicRng {
    /// Consume self and return the random bytes as a validated hex string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "encoding-hex"))]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let hex = DynamicRng::generate(16).into_hex();
    /// println!("random hex: {}", hex.expose_secret());
    /// # }
    /// ```
    pub fn into_hex(self) -> crate::encoding::hex::HexString {
        use hex;
        let hex = hex::encode(self.expose_secret());
        crate::encoding::hex::HexString::new_unchecked(hex)
    }

    /// Encode to hex without consuming self, for cases where raw is still needed briefly.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "encoding-hex"))]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let rng = DynamicRng::generate(16);
    /// let hex = rng.to_hex();
    /// // Use rng for something else here
    /// # }
    /// ```
    pub fn to_hex(&self) -> crate::encoding::hex::HexString {
        use hex;
        let hex = hex::encode(self.expose_secret());
        crate::encoding::hex::HexString::new_unchecked(hex)
    }
}

#[cfg(all(feature = "rand", feature = "encoding-base64"))]
impl DynamicRng {
    /// Consume self and return the random bytes as a validated base64 string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "encoding-base64"))]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let base64 = DynamicRng::generate(16).into_base64();
    /// println!("random base64: {}", base64.expose_secret());
    /// # }
    /// ```
    pub fn into_base64(self) -> crate::encoding::base64::Base64String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let encoded = URL_SAFE_NO_PAD.encode(self.expose_secret());
        crate::encoding::base64::Base64String::new_unchecked(encoded)
    }

    /// Encode to base64 without consuming self, for cases where raw is still needed briefly.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "encoding-base64"))]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let rng = DynamicRng::generate(16);
    /// let base64 = rng.to_base64();
    /// // Use rng for something else here
    /// # }
    /// ```
    pub fn to_base64(&self) -> crate::encoding::base64::Base64String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let encoded = URL_SAFE_NO_PAD.encode(self.expose_secret());
        crate::encoding::base64::Base64String::new_unchecked(encoded)
    }
}

impl From<DynamicRng> for Dynamic<Vec<u8>> {
    /// Convert a `DynamicRng` to `Dynamic`, transferring ownership.
    ///
    /// This preserves all security guarantees. The `DynamicRng` type
    /// ensures the value came from secure RNG, and this conversion
    /// transfers that value to `Dynamic` without exposing bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::{Dynamic, random::DynamicRng};
    /// let random: Dynamic<Vec<u8>> = DynamicRng::generate(64).into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(rng: DynamicRng) -> Self {
        rng.into_inner()
    }
}
