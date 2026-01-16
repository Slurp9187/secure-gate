use ::hex as hex_crate;

use crate::traits::expose_secret_ext::ExposeSecretExt;

// ========================================
// Consuming (into_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Consume self and return the random bytes as a validated hex string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    pub fn into_hex(self) -> crate::encoding::hex::HexString {
        let hex_str = hex_crate::encode(self.expose_secret());
        crate::encoding::hex::HexString::new_unchecked(hex_str)
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Consume self and return the random bytes as a validated hex string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    pub fn into_hex(self) -> crate::encoding::hex::HexString {
        let hex_str = hex_crate::encode(self.expose_secret());
        crate::encoding::hex::HexString::new_unchecked(hex_str)
    }
}

// ========================================
// Borrowing (to_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Borrow and encode the random bytes as a validated lowercase hex string (allocates).
    ///
    /// The original secret remains intact and usable.
    pub fn to_hex(&self) -> crate::encoding::hex::HexString {
        let hex_str = hex_crate::encode(self.expose_secret());
        crate::encoding::hex::HexString::new_unchecked(hex_str)
    }
}

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Borrow and encode the random bytes as a validated lowercase hex string (allocates).
    ///
    /// The original secret remains intact and usable.
    pub fn to_hex(&self) -> crate::encoding::hex::HexString {
        let hex_str = hex_crate::encode(self.expose_secret());
        crate::encoding::hex::HexString::new_unchecked(hex_str)
    }
}

// ========================================
// View types and their implementations
// ========================================

/// View struct for exposed hex strings, allowing decoding without direct access.
pub struct HexStringView<'a>(pub(crate) &'a String);

impl<'a> HexStringView<'a> {
    /// Decode the validated hex string into raw bytes (allocates).
    pub fn to_bytes(&self) -> Vec<u8> {
        hex_crate::decode(self.0.as_str()).expect("HexString is always valid")
    }
}

impl<'a> core::ops::Deref for HexStringView<'a> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl<'a> core::fmt::Debug for HexStringView<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<'a> core::fmt::Display for HexStringView<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl<'a> core::cmp::PartialEq<&str> for HexStringView<'a> {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

// ========================================
// expose_secret → view implementations
// ========================================

// ========================================
// Consuming decode (into_bytes) for secure zeroization
// ========================================

impl crate::encoding::hex::HexString {
    /// Decode the validated hex string into raw bytes, consuming and zeroizing the wrapper.
    pub fn into_bytes(self) -> Vec<u8> {
        hex_crate::decode(self.expose_secret()).expect("HexString is always valid")
    }
}
