// ========================================
// Consuming (into_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Consume self and return the random bytes as a validated hex string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    pub fn into_hex(self) -> crate::encoding::hex::HexString {
        self.expose_secret().to_hex()
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Consume self and return the random bytes as a validated hex string.
    ///
    /// The raw bytes are zeroized immediately after encoding.
    pub fn into_hex(self) -> crate::encoding::hex::HexString {
        self.expose_secret().to_hex()
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
        self.expose_secret().to_hex()
    }
}

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Borrow and encode the random bytes as a validated lowercase hex string (allocates).
    ///
    /// The original secret remains intact and usable.
    pub fn to_hex(&self) -> crate::encoding::hex::HexString {
        self.expose_secret().to_hex()
    }
}
