use ::base64 as base64_crate;

use base64_crate::engine::general_purpose::URL_SAFE_NO_PAD;

use base64_crate::Engine;

use crate::traits::expose_secret::ExposeSecret;

// ========================================
// Consuming (into_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Consume self and return the random bytes as a validated base64 string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    pub fn into_base64(self) -> crate::encoding::base64::Base64String {
        let encoded = URL_SAFE_NO_PAD.encode(self.expose_secret());
        crate::encoding::base64::Base64String::new_unchecked(encoded)
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Consume self and return the random bytes as a validated base64 string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    pub fn into_base64(self) -> crate::encoding::base64::Base64String {
        let encoded = URL_SAFE_NO_PAD.encode(self.expose_secret());
        crate::encoding::base64::Base64String::new_unchecked(encoded)
    }
}

// ========================================
// Borrowing (to_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Borrow and encode the random bytes as a validated base64 string (allocates).
    ///
    /// The original secret remains intact and usable.
    pub fn to_base64(&self) -> crate::encoding::base64::Base64String {
        let encoded = URL_SAFE_NO_PAD.encode(self.expose_secret());
        crate::encoding::base64::Base64String::new_unchecked(encoded)
    }
}

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Borrow and encode the random bytes as a validated base64 string (allocates).
    ///
    /// The original secret remains intact and usable.
    pub fn to_base64(&self) -> crate::encoding::base64::Base64String {
        let encoded = URL_SAFE_NO_PAD.encode(self.expose_secret());
        crate::encoding::base64::Base64String::new_unchecked(encoded)
    }
}

// ========================================
// View types and their implementations
// ========================================

/// View struct for exposed base64 strings, allowing decoding without direct access.
pub struct Base64StringView<'a>(pub(crate) &'a String);

impl<'a> Base64StringView<'a> {
    /// Decode the validated base64 string into raw bytes (allocates).
    pub fn to_bytes(&self) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(self.0.as_str())
            .expect("Base64String is always valid")
    }
}

impl<'a> core::ops::Deref for Base64StringView<'a> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl<'a> core::fmt::Debug for Base64StringView<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<'a> core::fmt::Display for Base64StringView<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl<'a> core::cmp::PartialEq<&str> for Base64StringView<'a> {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

// ========================================
// expose_secret → view implementations (removed)
// ========================================

// ========================================
// Consuming decode (into_bytes) for secure zeroization
// ========================================

impl crate::encoding::base64::Base64String {
    /// Decode the validated base64 string into raw bytes, consuming and zeroizing the wrapper.
    pub fn into_bytes(self) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(self.expose_secret())
            .expect("Base64String is always valid")
    }
}
