#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

// ========================================
// Consuming (into_) methods on RNG types
// ========================================

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

// ========================================
// Borrowing (to_) methods on RNG types
// ========================================

#[cfg(all(feature = "rand", feature = "encoding-hex"))]
impl<const N: usize> crate::FixedRng<N> {
    /// Borrow and encode the random bytes as a validated lowercase hex string (allocates).
    ///
    /// The original secret remains intact and usable.
    pub fn to_hex(&self) -> crate::encoding::hex::HexString {
        let hex_str = hex_crate::encode(self.expose_secret());
        crate::encoding::hex::HexString::new_unchecked(hex_str)
    }
}

#[cfg(all(feature = "rand", feature = "encoding-hex"))]
impl crate::DynamicRng {
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
#[cfg(feature = "encoding-hex")]
pub struct HexStringView<'a>(pub(crate) &'a String);

#[cfg(feature = "encoding-hex")]
impl<'a> HexStringView<'a> {
    /// Decode the validated hex string into raw bytes (allocates).
    pub fn to_bytes(&self) -> Vec<u8> {
        hex_crate::decode(self.0.as_str()).expect("HexString is always valid")
    }
}

#[cfg(feature = "encoding-hex")]
impl<'a> core::ops::Deref for HexStringView<'a> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

#[cfg(feature = "encoding-hex")]
impl<'a> core::fmt::Debug for HexStringView<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(feature = "encoding-hex")]
impl<'a> core::fmt::Display for HexStringView<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

#[cfg(feature = "encoding-hex")]
impl<'a> core::cmp::PartialEq<&str> for HexStringView<'a> {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

// ========================================
// expose_secret → view implementations
// ========================================

#[cfg(feature = "encoding-hex")]
impl crate::encoding::hex::HexString {
    pub fn expose_secret(&self) -> HexStringView<'_> {
        HexStringView(self.0.expose_secret())
    }
}

// ========================================
// Consuming decode (into_bytes) for secure zeroization
// ========================================

#[cfg(feature = "encoding-hex")]
impl crate::encoding::hex::HexString {
    /// Decode the validated hex string into raw bytes, consuming and zeroizing the wrapper.
    pub fn into_bytes(self) -> Vec<u8> {
        hex_crate::decode(self.expose_secret().0.as_str()).expect("HexString is always valid")
    }
}
