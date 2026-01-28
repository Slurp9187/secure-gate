#[cfg(feature = "alloc")]
extern crate alloc;
use alloc::boxed::Box;

#[cfg(feature = "rand")]
use rand::{rngs::OsRng, TryRngCore};

#[cfg(feature = "encoding-base64")]
use crate::traits::decoding::base64_url::FromBase64UrlStr;
#[cfg(feature = "encoding-bech32")]
use crate::traits::decoding::bech32::FromBech32Str;
#[cfg(feature = "encoding-bech32m")]
use crate::traits::decoding::bech32m::FromBech32mStr;
#[cfg(feature = "encoding-hex")]
use crate::traits::decoding::hex::FromHexStr;

/// Dynamic-sized heap-allocated secure secret wrapper.
///
/// This is a thin wrapper around `Box<T>` with enforced explicit exposure.
/// Suitable for dynamic-sized secrets like `String` or `Vec<u8>`.
/// The inner field is private, forcing all access through explicit methods.
///
/// Security invariants:
/// - No `Deref` or `AsRef` — prevents silent access.
/// - `Debug` is always redacted.
/// - With `zeroize`, wipes the entire allocation on drop (including spare capacity).
pub struct Dynamic<T: ?Sized> {
    inner: Box<T>,
}

impl<T: ?Sized> Dynamic<T> {
    /// Wrap a value by boxing it.
    ///
    /// Uses `Into<Box<T>>` for flexibility.
    #[inline(always)]
    pub fn new<U>(value: U) -> Self
    where
        U: Into<Box<T>>,
    {
        let inner = value.into();
        Self { inner }
    }
}

/// # Ergonomic helpers for common heap types
impl Dynamic<String> {}

impl<T> Dynamic<Vec<T>> {}

// From impls for Dynamic types
impl<T: ?Sized> From<Box<T>> for Dynamic<T> {
    /// Wrap a boxed value in a [`Dynamic`] secret.
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self { inner: boxed }
    }
}

impl From<&[u8]> for Dynamic<Vec<u8>> {
    /// Wrap a byte slice in a [`Dynamic`] [`Vec<u8>`].
    #[inline(always)]
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

impl From<&str> for Dynamic<String> {
    /// Wrap a string slice in a [`Dynamic`] [`String`].
    #[inline(always)]
    fn from(input: &str) -> Self {
        Self::new(input.to_string())
    }
}

impl<T: 'static> From<T> for Dynamic<T> {
    /// Wrap a value in a [`Dynamic`] secret by boxing it.
    #[inline(always)]
    fn from(value: T) -> Self {
        Self {
            inner: Box::new(value),
        }
    }
}

impl crate::ExposeSecret for Dynamic<String> {
    type Inner = String;
    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&String) -> R,
    {
        f(&self.inner)
    }
    #[inline(always)]
    fn expose_secret(&self) -> &String {
        &self.inner
    }
    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<T> crate::ExposeSecret for Dynamic<Vec<T>> {
    type Inner = Vec<T>;
    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Vec<T>) -> R,
    {
        f(&self.inner)
    }
    #[inline(always)]
    fn expose_secret(&self) -> &Vec<T> {
        &self.inner
    }
    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len() * core::mem::size_of::<T>()
    }
}

impl crate::ExposeSecretMut for Dynamic<String> {
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut String) -> R,
    {
        f(&mut self.inner)
    }
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut String {
        &mut self.inner
    }
}

impl<T> crate::ExposeSecretMut for Dynamic<Vec<T>> {
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Vec<T>) -> R,
    {
        f(&mut self.inner)
    }
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut Vec<T> {
        &mut self.inner
    }
}

// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Fill with fresh random bytes of the specified length using the System RNG.
    ///
    /// Panics on RNG failure for fail-fast crypto code. Guarantees secure entropy
    /// from system sources.
    #[inline]
    pub fn from_random(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failure is a program error");
        Self::from(bytes)
    }
}

// Decoding constructors — only available with encoding features.
#[cfg(feature = "encoding-hex")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decode a hex string into a Dynamic secret.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "encoding-hex")]
    /// use secure_gate::{Dynamic, ExposeSecret};
    /// let hex_string = "424344";
    /// let secret = Dynamic::try_from_hex(hex_string).unwrap();
    /// assert_eq!(secret.expose_secret().len(), 3);
    /// ```
    pub fn try_from_hex(s: &str) -> Result<Self, crate::error::HexError> {
        let bytes = s.try_from_hex()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "encoding-base64")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decode a base64url string into a Dynamic secret.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "encoding-base64")]
    /// use secure_gate::{Dynamic, ExposeSecret};
    /// let b64_string = "QkNE";
    /// let secret = Dynamic::try_from_base64url(b64_string).unwrap();
    /// assert_eq!(secret.expose_secret().len(), 3);
    /// ```
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        let bytes = s.try_from_base64url()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "encoding-bech32")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decode a bech32 string into a Dynamic secret, discarding the HRP.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "encoding-bech32")]
    /// use secure_gate::{Dynamic, ExposeSecret, ToBech32};
    /// let original: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
    /// let bech32_string = original.with_secret(|s| s.to_bech32("test"));
    /// let decoded = Dynamic::try_from_bech32(&bech32_string).unwrap();
    /// // HRP "test" is discarded, bytes are stored
    /// ```
    pub fn try_from_bech32(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "encoding-bech32m")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decode a bech32m string into a Dynamic secret, discarding the HRP.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "encoding-bech32m")]
    /// use secure_gate::Dynamic;
    /// // Note: Bech32m strings must be valid Bech32m format
    /// let bech32m_string = "abc1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
    /// let secret = Dynamic::try_from_bech32m(bech32m_string);
    /// // Returns Result<Dynamic<Vec<u8>>, Bech32Error>
    /// ```
    pub fn try_from_bech32m(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32m()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "ct-eq")]
impl<T: ?Sized> crate::ConstantTimeEq for Dynamic<T>
where
    T: crate::ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

// Constant-time equality for Dynamic types
#[cfg(feature = "ct-eq")]
impl Dynamic<String> {
    /// Constant-time equality comparison.
    ///
    /// Compares the byte contents of two instances in constant time
    /// to prevent timing attacks.
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.inner.as_bytes().ct_eq(other.inner.as_bytes())
    }
}

#[cfg(feature = "ct-eq")]
impl Dynamic<Vec<u8>> {
    /// Constant-time equality comparison.
    ///
    /// Compares the byte contents of two instances in constant time
    /// to prevent timing attacks.
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.inner.as_slice().ct_eq(other.inner.as_slice())
    }
}

#[cfg(feature = "ct-eq-hash")]
impl<T> crate::ConstantTimeEqExt for Dynamic<T>
where
    T: AsRef<[u8]> + crate::ConstantTimeEq + ?Sized,
{
    fn len(&self) -> usize {
        (*self.inner).as_ref().len()
    }

    fn ct_eq_hash(&self, other: &Self) -> bool {
        crate::traits::ct_eq_hash_bytes((*self.inner).as_ref(), (*other.inner).as_ref())
    }
    // ct_eq_auto uses default impl
}

// Redacted Debug implementation
impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(feature = "cloneable")]
impl<T: crate::CloneableSecret> Clone for Dynamic<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

#[cfg(feature = "serde-serialize")]
impl<T> serde::Serialize for Dynamic<T>
where
    T: crate::SerializableSecret,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

// Serde deserialization for Dynamic<String>
#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<String> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        Ok(Dynamic::new(s))
    }
}

// Serde deserialization for Dynamic<Vec<u8>>
#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<alloc::vec::Vec<u8>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec: alloc::vec::Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Ok(Dynamic::new(vec))
    }
}

// Zeroize integration
#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::Zeroize for Dynamic<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Zeroize on drop integration
#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::ZeroizeOnDrop for Dynamic<T> {}
