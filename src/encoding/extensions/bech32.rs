#[cfg(feature = "rand")]
use crate::Bech32EncodingError;

use crate::encoding::extensions::secure_encoding_ext::SecureEncodingExt;
use crate::traits::expose_secret::ExposeSecret;

// ========================================
// Consuming (into_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    pub fn try_into_bech32(
        self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, Bech32EncodingError> {
        self.expose_secret().try_to_bech32(hrp)
    }

    pub fn try_into_bech32m(
        self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, Bech32EncodingError> {
        self.expose_secret().try_to_bech32m(hrp)
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Consuming encode (raw random bytes zeroized immediately).
    pub fn try_into_bech32(
        self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, Bech32EncodingError> {
        self.expose_secret().try_to_bech32(hrp)
    }

    pub fn try_into_bech32m(
        self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, Bech32EncodingError> {
        self.expose_secret().try_to_bech32m(hrp)
    }
}

// ========================================
// Borrowing (to_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Borrowing encode (original random remains usable).
    pub fn try_to_bech32(
        &self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, Bech32EncodingError> {
        self.expose_secret().try_to_bech32(hrp)
    }

    pub fn try_to_bech32m(
        &self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, Bech32EncodingError> {
        self.expose_secret().try_to_bech32m(hrp)
    }
}

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    pub fn try_to_bech32(
        &self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, Bech32EncodingError> {
        self.expose_secret().try_to_bech32(hrp)
    }

    pub fn try_to_bech32m(
        &self,
        hrp: &str,
    ) -> Result<crate::encoding::bech32::Bech32String, Bech32EncodingError> {
        self.expose_secret().try_to_bech32m(hrp)
    }
}
