#[cfg(feature = "rand")]
use super::SecureEncodingExt;
#[cfg(feature = "rand")]
use crate::traits::expose_secret::ExposeSecret;

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Borrowing encode (original random remains usable).
    pub fn to_base64url(&self) -> crate::encoding::base64::Base64String {
        self.expose_secret().to_base64url()
    }

    /// Consuming encode (raw random bytes zeroized immediately).
    pub fn into_base64url(self) -> crate::encoding::base64::Base64String {
        self.expose_secret().to_base64url()
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Borrowing encode (original random remains usable).
    pub fn to_base64url(&self) -> crate::encoding::base64::Base64String {
        self.expose_secret().to_base64url()
    }

    /// Consuming encode (raw random bytes zeroized immediately).
    pub fn into_base64url(self) -> crate::encoding::base64::Base64String {
        self.expose_secret().to_base64url()
    }
}
