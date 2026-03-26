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
//! use secure_gate::{Dynamic, RevealSecret};
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
use crate::RevealSecret;

// Encoding traits
#[cfg(feature = "encoding-base64")]
use crate::traits::encoding::base64_url::ToBase64Url;
#[cfg(feature = "encoding-hex")]
use crate::traits::encoding::hex::ToHex;

#[cfg(feature = "rand")]
use rand::{TryCryptoRng, TryRng, rngs::SysRng};

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
/// No `Deref`, `AsRef`, or `Copy` by default — all access requires
/// [`expose_secret()`](crate::RevealSecret::expose_secret) or
/// [`with_secret()`](crate::RevealSecret::with_secret) (scoped, preferred).
/// For the common concrete types, [`Dynamic::<Vec<u8>>::new_with`](Dynamic::new_with) and
/// [`Dynamic::<String>::new_with`](Dynamic::new_with) are the matching scoped constructors —
/// closures that write directly into the wrapper. [`new(value)`](Dynamic::new) remains
/// available as the ergonomic default. `Debug` always prints `[REDACTED]`.
pub struct Dynamic<T: ?Sized + zeroize::Zeroize> {
    inner: Box<T>,
}

impl<T: ?Sized + zeroize::Zeroize> Dynamic<T> {
    /// Wraps `value` in a `Box<T>` and returns a `Dynamic<T>`.
    ///
    /// Accepts any type that implements `Into<Box<T>>` — including owned values,
    /// `Box<T>`, `String`, `Vec<u8>`, `&str` (via the blanket `From<&str>` impl), etc.
    ///
    /// Equivalent to `Dynamic::from(value)` — `#[doc(alias = "from")]` is set so both
    /// names appear in docs.rs search.
    ///
    /// Requires the `alloc` feature (which `Dynamic<T>` itself always requires).
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
    /// Encodes the secret bytes as a lowercase hex string.
    ///
    /// Delegates to [`ToHex::to_hex`](crate::ToHex::to_hex) on the inner `Vec<u8>`.
    /// Requires the `encoding-hex` feature.
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_hex())
    }

    /// Encodes the secret bytes as an uppercase hex string.
    ///
    /// Delegates to [`ToHex::to_hex_upper`](crate::ToHex::to_hex_upper) on the inner `Vec<u8>`.
    /// Requires the `encoding-hex` feature.
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex_upper(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_hex_upper())
    }

    /// Encodes the secret bytes as an unpadded Base64url string.
    ///
    /// Delegates to [`ToBase64Url::to_base64url`](crate::ToBase64Url::to_base64url) on the inner `Vec<u8>`.
    /// Requires the `encoding-base64` feature.
    #[cfg(feature = "encoding-base64")]
    #[inline]
    pub fn to_base64url(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_base64url())
    }

    /// Transfers `protected` bytes into a freshly boxed `Vec`, keeping
    /// [`zeroize::Zeroizing`] alive across the only allocation that can panic.
    ///
    /// # Panic safety
    ///
    /// `Box::new(Vec::new())` is the sole allocation point — just the 24-byte
    /// `Vec` header, no data buffer. If it panics (OOM), `protected` is still
    /// in scope and `Zeroizing::drop` zeroes the secret bytes during unwind.
    /// After the swap, `protected` holds an empty `Vec` (no-op to zeroize) and
    /// `Dynamic::from(boxed)` is an infallible struct-field assignment.
    ///
    /// Note: `Box::new(*protected)` would be cleaner but does not compile —
    /// `Zeroizing` implements `Deref` (returning `&T`), not a move-out, so
    /// `*protected` yields a reference rather than an owned value (E0507).
    #[cfg(any(
        feature = "encoding-hex",
        feature = "encoding-base64",
        feature = "encoding-bech32",
        feature = "encoding-bech32m",
    ))]
    #[inline(always)]
    fn from_protected_bytes(mut protected: zeroize::Zeroizing<alloc::vec::Vec<u8>>) -> Self {
        // Only fallible allocation; protected stays live across it for panic-safety
        let mut boxed = Box::new(alloc::vec::Vec::new());
        core::mem::swap(&mut *boxed, &mut *protected);
        Self::from(boxed)
    }

    /// Closure-based constructor for consistent API with [`Fixed::new_with`](crate::Fixed::new_with).
    /// The actual secret data is allocated on the heap; this method exists
    /// for ergonomic uniformity across the crate.
    #[inline(always)]
    pub fn new_with<F>(f: F) -> Self
    where
        F: FnOnce(&mut alloc::vec::Vec<u8>),
    {
        let mut v = alloc::vec::Vec::new();
        f(&mut v);
        Self::new(v)
    }
}

impl Dynamic<alloc::string::String> {
    /// Closure-based constructor for consistent API with [`Fixed::new_with`](crate::Fixed::new_with).
    /// The actual secret data is allocated on the heap; this method exists
    /// for ergonomic uniformity across the crate.
    #[inline(always)]
    pub fn new_with<F>(f: F) -> Self
    where
        F: FnOnce(&mut alloc::string::String),
    {
        let mut s = alloc::string::String::new();
        f(&mut s);
        Self::new(s)
    }
}

// RevealSecret
impl crate::RevealSecret for Dynamic<String> {
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

impl<T: zeroize::Zeroize> crate::RevealSecret for Dynamic<Vec<T>> {
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

// RevealSecretMut
impl crate::RevealSecretMut for Dynamic<String> {
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

impl<T: zeroize::Zeroize> crate::RevealSecretMut for Dynamic<Vec<T>> {
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
    /// Fills a new `Vec<u8>` with `len` cryptographically secure random bytes and wraps it.
    ///
    /// Uses the system RNG ([`SysRng`](rand::rngs::SysRng)). Requires the `rand` feature (and
    /// `alloc`, which `Dynamic<Vec<u8>>` always needs).
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails to provide bytes ([`TryRng::try_fill_bytes`](rand::TryRng::try_fill_bytes)
    /// returns `Err`). This is treated as a fatal environment error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "rand"))]
    /// use secure_gate::{Dynamic, RevealSecret};
    ///
    /// # #[cfg(all(feature = "alloc", feature = "rand"))]
    /// # {
    /// let nonce: Dynamic<Vec<u8>> = Dynamic::from_random(24);
    /// assert_eq!(nonce.len(), 24);
    /// # }
    /// ```
    #[inline]
    pub fn from_random(len: usize) -> Self {
        Self::new_with(|v| {
            v.resize(len, 0u8);
            SysRng
                .try_fill_bytes(v)
                .expect("SysRng failure is a program error");
        })
    }

    /// Allocates a `Vec<u8>` of length `len`, fills it from `rng`, and wraps it.
    ///
    /// Accepts any [`TryCryptoRng`](rand::TryCryptoRng) + [`TryRng`](rand::TryRng) — for example,
    /// a seeded [`StdRng`](rand::rngs::StdRng) for deterministic tests. Requires the `rand`
    /// feature and `alloc` (implicit — [`Dynamic<T>`](crate::Dynamic) itself requires it).
    ///
    /// # Errors
    ///
    /// Returns `R::Error` if [`try_fill_bytes`](rand::TryRng::try_fill_bytes) fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "rand"))]
    /// # {
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    /// use secure_gate::Dynamic;
    ///
    /// let mut rng = StdRng::from_seed([9u8; 32]);
    /// let nonce: Dynamic<Vec<u8>> = Dynamic::from_rng(24, &mut rng).expect("rng fill");
    /// # }
    /// ```
    #[inline]
    pub fn from_rng<R: TryRng + TryCryptoRng>(
        len: usize,
        rng: &mut R,
    ) -> Result<Self, R::Error> {
        let mut result = Ok(());
        let this = Self::new_with(|v| {
            v.resize(len, 0u8);
            result = rng.try_fill_bytes(v);
        });
        result.map(|_| this)
    }
}

// Decoding constructors
#[cfg(feature = "encoding-hex")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a lowercase hex string into `Dynamic<Vec<u8>>`.
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    pub fn try_from_hex(s: &str) -> Result<Self, crate::error::HexError> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_hex()?,
        )))
    }
}

#[cfg(feature = "encoding-base64")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a Base64url (unpadded) string into `Dynamic<Vec<u8>>`.
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_base64url()?,
        )))
    }
}

#[cfg(feature = "encoding-bech32")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a Bech32 (BIP-173) string into `Dynamic<Vec<u8>>`.
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    ///
    /// # Warning
    ///
    /// The HRP is **not validated** — any HRP will be accepted as long as the checksum
    /// is valid. For security-critical code where cross-protocol confusion must be
    /// prevented, use [`try_from_bech32`](Self::try_from_bech32).
    pub fn try_from_bech32_unchecked(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32_unchecked()?;
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(bytes)))
    }

    /// Decodes a Bech32 (BIP-173) string into `Dynamic<Vec<u8>>`, validating that the HRP
    /// matches `expected_hrp` (case-insensitive).
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    ///
    /// Prefer this over [`try_from_bech32_unchecked`](Self::try_from_bech32_unchecked) in
    /// security-critical code to prevent cross-protocol confusion attacks.
    pub fn try_from_bech32(s: &str, expected_hrp: &str) -> Result<Self, crate::error::Bech32Error> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_bech32(expected_hrp)?,
        )))
    }
}

#[cfg(feature = "encoding-bech32m")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a Bech32m (BIP-350) string into `Dynamic<Vec<u8>>`.
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    ///
    /// # Warning
    ///
    /// The HRP is **not validated** — any HRP will be accepted as long as the checksum
    /// is valid. For security-critical code where cross-protocol confusion must be
    /// prevented, use [`try_from_bech32m`](Self::try_from_bech32m).
    pub fn try_from_bech32m_unchecked(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32m_unchecked()?;
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(bytes)))
    }

    /// Decodes a Bech32m (BIP-350) string into `Dynamic<Vec<u8>>`, validating that the HRP
    /// matches `expected_hrp` (case-insensitive).
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    ///
    /// Prefer this over [`try_from_bech32m_unchecked`](Self::try_from_bech32m_unchecked) in
    /// security-critical code to prevent cross-protocol confusion attacks.
    pub fn try_from_bech32m(
        s: &str,
        expected_hrp: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_bech32m(expected_hrp)?,
        )))
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

/// Default maximum byte length accepted when deserializing `Dynamic<Vec<u8>>` or
/// `Dynamic<String>` via the standard `serde::Deserialize` impl (1 MiB).
///
/// Pass a custom value to [`Dynamic::deserialize_with_limit`] when a different
/// ceiling is required.
///
/// **Important:** this limit is enforced *after* the upstream deserializer has fully
/// materialized the payload. It is a **result-length acceptance bound**, not a
/// pre-allocation DoS guard. For untrusted input, enforce size limits at the
/// transport or parser layer upstream.
#[cfg(feature = "serde-deserialize")]
pub const MAX_DESERIALIZE_BYTES: usize = 1_048_576;

#[cfg(feature = "serde-deserialize")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Deserializes into `Dynamic<Vec<u8>>`, rejecting payloads larger than `limit` bytes.
    ///
    /// The standard [`serde::Deserialize`] impl calls this with [`MAX_DESERIALIZE_BYTES`].
    /// Use this method directly when you need a tighter or looser ceiling.
    ///
    /// The intermediate buffer is kept inside a `Zeroizing` wrapper until after the `Box`
    /// allocation completes, guaranteeing zeroization even on OOM panic. Oversized buffers
    /// are also zeroized before the error is returned.
    ///
    /// **Important:** this limit is enforced *after* the upstream deserializer has fully
    /// materialized the payload. It is a **result-length acceptance bound**, not a
    /// pre-allocation DoS guard. For untrusted input, enforce size limits at the
    /// transport or parser layer upstream.
    pub fn deserialize_with_limit<'de, D>(deserializer: D, limit: usize) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut buf: zeroize::Zeroizing<alloc::vec::Vec<u8>> =
            zeroize::Zeroizing::new(serde::Deserialize::deserialize(deserializer)?);
        if buf.len() > limit {
            // buf drops here → Zeroizing zeros the oversized buffer before deallocation
            return Err(serde::de::Error::custom(
                "deserialized secret exceeds maximum size",
            ));
        }
        // Only fallible allocation; protected stays live across it for panic-safety
        let mut boxed = Box::new(alloc::vec::Vec::new());
        core::mem::swap(&mut *boxed, &mut *buf);
        Ok(Self::from(boxed))
    }
}

#[cfg(feature = "serde-deserialize")]
impl Dynamic<String> {
    /// Deserializes into `Dynamic<String>`, rejecting payloads larger than `limit` bytes.
    ///
    /// The standard [`serde::Deserialize`] impl calls this with [`MAX_DESERIALIZE_BYTES`].
    /// Use this method directly when you need a tighter or looser ceiling.
    ///
    /// The intermediate buffer is kept inside a `Zeroizing` wrapper until after the `Box`
    /// allocation completes, guaranteeing zeroization even on OOM panic. Oversized buffers
    /// are also zeroized before the error is returned.
    ///
    /// **Important:** this limit is enforced *after* the upstream deserializer has fully
    /// materialized the payload. It is a **result-length acceptance bound**, not a
    /// pre-allocation DoS guard. For untrusted input, enforce size limits at the
    /// transport or parser layer upstream.
    pub fn deserialize_with_limit<'de, D>(deserializer: D, limit: usize) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut buf: zeroize::Zeroizing<alloc::string::String> =
            zeroize::Zeroizing::new(serde::Deserialize::deserialize(deserializer)?);
        if buf.len() > limit {
            // buf drops here → Zeroizing zeros the oversized buffer before deallocation
            return Err(serde::de::Error::custom(
                "deserialized secret exceeds maximum size",
            ));
        }
        // Only fallible allocation; protected stays live across it for panic-safety
        let mut boxed = Box::new(alloc::string::String::new());
        core::mem::swap(&mut *boxed, &mut *buf);
        Ok(Self::from(boxed))
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<alloc::vec::Vec<u8>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::deserialize_with_limit(deserializer, MAX_DESERIALIZE_BYTES)
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<String> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::deserialize_with_limit(deserializer, MAX_DESERIALIZE_BYTES)
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
