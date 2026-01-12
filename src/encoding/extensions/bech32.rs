#[cfg(feature = "encoding-bech32")]
#[allow(unused_imports)] // Clippy bug: doesn't recognize use in generics
use ::bech32::{decode, encode, Hrp};

// ========================================
// Consuming (into_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Consume self and return the random bytes as a validated Bech32 string with the specified HRP.
    ///
    /// The raw bytes are zeroized immediately after encoding (via drop of `self`).
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid or encoding fails (should never happen for valid random bytes).
    pub fn into_bech32(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = encode::<::bech32::Bech32>(hrp, self.expose_secret())
            .expect("encoding valid random bytes cannot fail");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        )
    }

    /// Consume self and return the random bytes as a validated Bech32m string with the specified HRP.
    ///
    /// The raw bytes are zeroized immediately after encoding (via drop of `self`).
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid or encoding fails (should never happen for valid random bytes).
    pub fn into_bech32m(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = encode::<::bech32::Bech32m>(hrp, self.expose_secret())
            .expect("encoding valid random bytes cannot fail");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        )
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Consume self and return the random bytes as a validated Bech32 string with the specified HRP.
    ///
    /// The raw bytes are zeroized immediately after encoding (via drop of `self`).
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid or encoding fails (should never happen for valid random bytes).
    pub fn into_bech32(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = encode::<::bech32::Bech32>(hrp, self.expose_secret())
            .expect("encoding valid random bytes cannot fail");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        )
    }

    /// Consume self and return the random bytes as a validated Bech32m string with the specified HRP.
    ///
    /// The raw bytes are zeroized immediately after encoding (via drop of `self`).
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid or encoding fails (should never happen for valid random bytes).
    pub fn into_bech32m(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = encode::<::bech32::Bech32m>(hrp, self.expose_secret())
            .expect("encoding valid random bytes cannot fail");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        )
    }
}

// ========================================
// Borrowing (to_) methods on RNG types
// ========================================

#[cfg(feature = "rand")]
impl<const N: usize> crate::FixedRandom<N> {
    /// Borrow and encode the random bytes as a validated Bech32 string with the specified HRP (allocates).
    ///
    /// The original secret remains intact and usable.
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid (should be validated externally if needed).
    pub fn to_bech32(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = encode::<::bech32::Bech32>(hrp, self.expose_secret())
            .expect("encoding valid bytes cannot fail");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        )
    }

    /// Borrow and encode the random bytes as a validated Bech32m string with the specified HRP (allocates).
    ///
    /// The original secret remains intact and usable.
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid (should be validated externally if needed).
    pub fn to_bech32m(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = encode::<::bech32::Bech32m>(hrp, self.expose_secret())
            .expect("encoding valid bytes cannot fail");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        )
    }
}

#[cfg(feature = "rand")]
impl crate::DynamicRandom {
    /// Borrow and encode the random bytes as a validated Bech32 string with the specified HRP (allocates).
    ///
    /// The original secret remains intact and usable.
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid (should be validated externally if needed).
    pub fn to_bech32(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = encode::<::bech32::Bech32>(hrp, self.expose_secret())
            .expect("encoding valid bytes cannot fail");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32,
        )
    }

    /// Borrow and encode the random bytes as a validated Bech32m string with the specified HRP (allocates).
    ///
    /// The original secret remains intact and usable.
    ///
    /// # Panics
    ///
    /// Panics if the HRP is invalid (should be validated externally if needed).
    pub fn to_bech32m(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
        let hrp = Hrp::parse(hrp).expect("invalid HRP");
        let encoded = encode::<::bech32::Bech32m>(hrp, self.expose_secret())
            .expect("encoding valid bytes cannot fail");
        crate::encoding::bech32::Bech32String::new_unchecked(
            encoded,
            crate::encoding::bech32::EncodingVariant::Bech32m,
        )
    }
}

// ========================================
// View types and their implementations
// ========================================

/// View struct for exposed Bech32 strings, allowing decoding without direct access.
pub struct Bech32StringView<'a>(pub(crate) &'a String);

impl<'a> Bech32StringView<'a> {
    /// Decode the validated Bech32/Bech32m string into raw bytes (allocates).
    pub fn to_bytes(&self) -> Vec<u8> {
        let (_, data) = decode(self.0.as_str()).expect("Bech32String is always valid");
        data
    }
}

impl<'a> core::ops::Deref for Bech32StringView<'a> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl<'a> core::fmt::Debug for Bech32StringView<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<'a> core::fmt::Display for Bech32StringView<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl<'a> core::cmp::PartialEq<&str> for Bech32StringView<'a> {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

// ========================================
// expose_secret → view implementations
// ========================================

impl crate::encoding::bech32::Bech32String {
    pub fn expose_secret(&self) -> Bech32StringView<'_> {
        Bech32StringView(self.inner.expose_secret())
    }
}

// ========================================
// Consuming decode (into_bytes) for secure zeroization
// ========================================

impl crate::encoding::bech32::Bech32String {
    /// Decode the validated Bech32/Bech32m string into raw bytes, consuming and zeroizing the wrapper.
    pub fn into_bytes(self) -> Vec<u8> {
        let (_, data) =
            decode(self.expose_secret().0.as_str()).expect("Bech32String is always valid");
        data
    }
}
