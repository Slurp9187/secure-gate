//! Heap-allocated wrapper for variable-length secrets.
//!
//! Provides [`Dynamic<T>`], a zero-cost wrapper enforcing explicit access to sensitive data.
//! Treat secrets as radioactive — minimize exposure surface.
//!
//! **Inner type must implement `Zeroize`** for automatic zeroization on drop (including spare capacity).
//! Requires the `alloc` feature.
//!
//! # Examples
//!
//! ```rust
//! # #[cfg(feature = "alloc")]
//! use secure_gate::{Dynamic, ExposeSecret};
//!
//! # #[cfg(feature = "alloc")]
//! {
//! let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3, 4]);
//! let sum = secret.with_secret(|s| s.iter().sum::<u8>());
//! assert_eq!(sum, 10);
//! # }
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;
use alloc::boxed::Box;
use zeroize::Zeroize;

#[cfg(any(feature = "encoding-hex", feature = "encoding-base64"))]
use crate::ExposeSecret;

// Encoding traits
#[cfg(feature = "encoding-base64")]
use crate::traits::encoding::base64_url::ToBase64Url;
#[cfg(feature = "encoding-hex")]
use crate::traits::encoding::hex::ToHex;

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

/// Zero-cost heap-allocated wrapper for variable-length secrets.
///
/// Requires `alloc`. **Inner type must implement `Zeroize`** for automatic zeroization on drop
/// (including spare capacity in `Vec`/`String`).
///
/// No `Deref`, `AsRef`, or `Copy` by default. `Debug` always prints `[REDACTED]`.
pub struct Dynamic<T: ?Sized + zeroize::Zeroize> {
    inner: Box<T>,
}

impl<T: ?Sized + zeroize::Zeroize> Dynamic<T> {
    #[doc(alias = "from")]
    #[inline(always)]
    pub fn new<U>(value: U) -> Self
    where
        U: Into<Box<T>>,
    {
        let inner = value.into();
        Self { inner }
    }
}

// From impls
impl<T: ?Sized + zeroize::Zeroize> From<Box<T>> for Dynamic<T> {
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self { inner: boxed }
    }
}

impl From<&[u8]> for Dynamic<Vec<u8>> {
    #[inline(always)]
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

impl From<&str> for Dynamic<String> {
    #[inline(always)]
    fn from(input: &str) -> Self {
        Self::new(input.to_string())
    }
}

impl<T: 'static + zeroize::Zeroize> From<T> for Dynamic<T> {
    #[inline(always)]
    fn from(value: T) -> Self {
        Self {
            inner: Box::new(value),
        }
    }
}

// Encoding helpers for Dynamic<Vec<u8>>
impl Dynamic<Vec<u8>> {
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_hex())
    }

    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex_upper(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_hex_upper())
    }

    #[cfg(feature = "encoding-base64")]
    #[inline]
    pub fn to_base64url(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_base64url())
    }

    /// Moves `bytes` through a [`zeroize::Zeroizing`] wrapper, ensuring the
    /// allocation is zeroized if a panic occurs between a successful decode and
    /// [`Self::new`]. Uses `core::mem::take` — no extra heap allocation.
    #[inline(always)]
    fn protect_decode_result(bytes: alloc::vec::Vec<u8>) -> alloc::vec::Vec<u8> {
        let mut protected = zeroize::Zeroizing::new(bytes);
        core::mem::take(&mut *protected)
    }
}

impl Dynamic<String> {
    /// Moves `s` through a [`zeroize::Zeroizing`] wrapper, ensuring the
    /// allocation is zeroized if a panic occurs between a successful decode and
    /// [`Self::new`]. Uses `core::mem::take` — no extra heap allocation.
    #[inline(always)]
    fn protect_decode_result(s: alloc::string::String) -> alloc::string::String {
        let mut protected = zeroize::Zeroizing::new(s);
        core::mem::take(&mut *protected)
    }
}

// ExposeSecret
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

impl<T: zeroize::Zeroize> crate::ExposeSecret for Dynamic<Vec<T>> {
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

// ExposeSecretMut
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

impl<T: zeroize::Zeroize> crate::ExposeSecretMut for Dynamic<Vec<T>> {
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

// Random generation
#[cfg(feature = "rand")]
impl Dynamic<alloc::vec::Vec<u8>> {
    #[inline]
    pub fn from_random(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failure is a program error");
        Self::from(bytes)
    }
}

// Decoding constructors
#[cfg(feature = "encoding-hex")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a lowercase hex string into `Dynamic<Vec<u8>>`.
    ///
    /// The temporary decode buffer is wrapped with `Zeroizing` (consistent with `Fixed<T>`).
    pub fn try_from_hex(s: &str) -> Result<Self, crate::error::HexError> {
        let bytes = s.try_from_hex()?;
        Ok(Self::new(Self::protect_decode_result(bytes)))
    }
}

#[cfg(feature = "encoding-base64")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a Base64url (unpadded) string into `Dynamic<Vec<u8>>`.
    ///
    /// The temporary decode buffer is wrapped with `Zeroizing` (consistent with `Fixed<T>`).
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        let bytes = s.try_from_base64url()?;
        Ok(Self::new(Self::protect_decode_result(bytes)))
    }
}

#[cfg(feature = "encoding-bech32")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a Bech32 (BIP-173) string into `Dynamic<Vec<u8>>`.
    ///
    /// The temporary decode buffer is wrapped with `Zeroizing` (consistent with `Fixed<T>`).
    ///
    /// # Warning
    ///
    /// The HRP is **not validated** — any HRP will be accepted as long as the checksum
    /// is valid. For security-critical code where cross-protocol confusion must be
    /// prevented, use [`try_from_bech32_expect_hrp`](Self::try_from_bech32_expect_hrp).
    pub fn try_from_bech32(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32()?;
        Ok(Self::new(Self::protect_decode_result(bytes)))
    }

    /// Decodes a Bech32 (BIP-173) string into `Dynamic<Vec<u8>>`, validating that the HRP
    /// matches `expected_hrp` (case-insensitive).
    ///
    /// The temporary decode buffer is wrapped with `Zeroizing` (consistent with `Fixed<T>`).
    ///
    /// Prefer this over [`try_from_bech32`](Self::try_from_bech32) in security-critical code
    /// to prevent cross-protocol confusion attacks.
    pub fn try_from_bech32_expect_hrp(s: &str, expected_hrp: &str) -> Result<Self, crate::error::Bech32Error> {
        let bytes = s.try_from_bech32_expect_hrp(expected_hrp)?;
        Ok(Self::new(Self::protect_decode_result(bytes)))
    }
}

#[cfg(feature = "encoding-bech32m")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a Bech32m (BIP-350) string into `Dynamic<Vec<u8>>`.
    ///
    /// The temporary decode buffer is wrapped with `Zeroizing` (consistent with `Fixed<T>`).
    ///
    /// # Warning
    ///
    /// The HRP is **not validated** — any HRP will be accepted as long as the checksum
    /// is valid. For security-critical code where cross-protocol confusion must be
    /// prevented, use [`try_from_bech32m_expect_hrp`](Self::try_from_bech32m_expect_hrp).
    pub fn try_from_bech32m(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32m()?;
        Ok(Self::new(Self::protect_decode_result(bytes)))
    }

    /// Decodes a Bech32m (BIP-350) string into `Dynamic<Vec<u8>>`, validating that the HRP
    /// matches `expected_hrp` (case-insensitive).
    ///
    /// The temporary decode buffer is wrapped with `Zeroizing` (consistent with `Fixed<T>`).
    ///
    /// Prefer this over [`try_from_bech32m`](Self::try_from_bech32m) in security-critical code
    /// to prevent cross-protocol confusion attacks.
    pub fn try_from_bech32m_expect_hrp(s: &str, expected_hrp: &str) -> Result<Self, crate::error::Bech32Error> {
        let bytes = s.try_from_bech32m_expect_hrp(expected_hrp)?;
        Ok(Self::new(Self::protect_decode_result(bytes)))
    }
}

// ConstantTimeEq
#[cfg(feature = "ct-eq")]
impl<T: ?Sized + zeroize::Zeroize> crate::ConstantTimeEq for Dynamic<T>
where
    T: crate::ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "ct-eq-hash")]
impl<T: ?Sized + zeroize::Zeroize> crate::ConstantTimeEqExt for Dynamic<T>
where
    T: AsRef<[u8]> + crate::ConstantTimeEq,
{
    fn len(&self) -> usize {
        (*self.inner).as_ref().len()
    }

    fn ct_eq_hash(&self, other: &Self) -> bool {
        crate::traits::ct_eq_hash_bytes((*self.inner).as_ref(), (*other.inner).as_ref())
    }
}

// Debug
impl<T: ?Sized + zeroize::Zeroize> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// Clone
#[cfg(feature = "cloneable")]
impl<T: zeroize::Zeroize + crate::CloneableSecret> Clone for Dynamic<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

// Serialize
#[cfg(feature = "serde-serialize")]
impl<T: zeroize::Zeroize + crate::SerializableSecret> serde::Serialize for Dynamic<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

// Deserialize
#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<String> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        Ok(Self::new(Self::protect_decode_result(s)))
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<alloc::vec::Vec<u8>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec: alloc::vec::Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Ok(Self::new(Self::protect_decode_result(vec)))
    }
}

// Zeroize + Drop (now always present with bound)
impl<T: ?Sized + zeroize::Zeroize> zeroize::Zeroize for Dynamic<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: ?Sized + zeroize::Zeroize> Drop for Dynamic<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: ?Sized + zeroize::Zeroize> zeroize::ZeroizeOnDrop for Dynamic<T> {}
