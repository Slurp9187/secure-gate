use super::SecureEncodingExt;
#[cfg(feature = "rand")]
use crate::traits::expose_secret::ExposeSecret;
use crate::Bech32EncodingError;

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
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
