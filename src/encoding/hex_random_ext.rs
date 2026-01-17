#[cfg(feature = "rand")]
use super::SecureEncodingExt;
#[cfg(feature = "rand")]
use crate::traits::expose_secret::ExposeSecret;

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Borrowing encode (original random remains usable).
    pub fn to_hex(&self) -> crate::encoding::hex::HexString {
        self.expose_secret().to_hex()
    }

    /// Consuming encode (raw random bytes zeroized immediately).
    pub fn into_hex(self) -> crate::encoding::hex::HexString {
        self.expose_secret().to_hex()
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Borrowing encode (original random remains usable).
    pub fn to_hex(&self) -> crate::encoding::hex::HexString {
        self.expose_secret().to_hex()
    }

    /// Consuming encode (raw random bytes zeroized immediately).
    pub fn into_hex(self) -> crate::encoding::hex::HexString {
        self.expose_secret().to_hex()
    }
}
