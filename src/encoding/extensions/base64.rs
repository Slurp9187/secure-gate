use crate::encoding::extensions::secure_encoding_ext::SecureEncodingExt;
use crate::traits::expose_secret::ExposeSecret;

// ========================================
// Consuming (into_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Consuming encode (raw random bytes zeroized immediately).
    pub fn into_base64url(self) -> crate::encoding::base64::Base64String {
        self.expose_secret().to_base64url()
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Consuming encode (raw random bytes zeroized immediately).
    pub fn into_base64url(self) -> crate::encoding::base64::Base64String {
        self.expose_secret().to_base64url()
    }
}

// ========================================
// Borrowing (to_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Borrowing encode (original random remains usable).
    pub fn to_base64url(&self) -> crate::encoding::base64::Base64String {
        self.expose_secret().to_base64url()
    }
}

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Borrowing encode (original random remains usable).
    pub fn to_base64url(&self) -> crate::encoding::base64::Base64String {
        self.expose_secret().to_base64url()
    }
}
