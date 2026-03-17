//! Heap-allocated wrapper for variable-length secrets.
//!
//! Provides [`Dynamic<T>`], a zero-cost wrapper enforcing explicit access to sensitive data.
//! Treat secrets as radioactive — minimize exposure surface.
//!
//! # Features
//!
//! - **Core**: Requires `alloc` — basic wrapping and explicit exposure
//! - **Zeroization**: With `zeroize` — wipes memory on drop (including spare capacity)
//! - **Random Generation**: With `rand` — generate secure random bytes via `from_random()`
//! - **Encoding/Decoding**: With `encoding-*` — hex, base64url, bech32, bech32m support
//! - **Constant-Time Eq**: With `ct-eq` or `ct-eq-hash` — secure comparisons
//! - **Serde**: With `serde-*` — serialize/deserialize (exposes secrets; use with care)
//! - **Cloneable**: With `cloneable` — clone where inner type allows
//!
//! # Examples
//!
//! Basic construction and access:
//!
//! ```rust
//! use secure_gate::{Dynamic, ExposeSecret};
//!
//! let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3, 4]);
//!
//! // Scoped access (recommended — minimizes exposure lifetime)
//! let sum = secret.with_secret(|s| s.iter().sum::<u8>());
//! assert_eq!(sum, 10);
//!
//! // Direct access (auditable escape hatch)
//! assert_eq!(secret.expose_secret()[0], 1);
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

use alloc::boxed::Box;

use crate::ExposeSecret; // Required for `with_secret` / `expose_secret` in helpers

// Encoding traits — needed so the helper methods can call `.to_hex()` etc.
#[cfg(feature = "encoding-base64")]
use crate::traits::encoding::base64_url::ToBase64Url;
#[cfg(feature = "encoding-bech32")]
use crate::traits::encoding::bech32::ToBech32;
#[cfg(feature = "encoding-bech32m")]
use crate::traits::encoding::bech32m::ToBech32m;
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
/// Requires `alloc`. Suitable for API keys, passwords, tokens, and any secret
/// whose size is not known at compile time.
///
/// No `Deref`, `AsRef`, or `Copy` by default — all access requires
/// [`expose_secret()`](crate::ExposeSecret::expose_secret) (direct, auditable) or
/// [`with_secret()`](crate::ExposeSecret::with_secret) (scoped, recommended).
/// `Debug` always prints `[REDACTED]`. When `zeroize` is enabled, the full
/// allocation (including `Vec`/`String` spare capacity) is wiped on drop.
/// Performance indistinguishable from raw types;
/// see [ZERO_COST_WRAPPERS.md](https://github.com/Slurp9187/secure-gate/blob/main/ZERO_COST_WRAPPERS.md).
///
/// # Examples
///
/// Basic construction and access:
///
/// ```rust
/// use secure_gate::{Dynamic, ExposeSecret};
///
/// let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3, 4]);
///
/// // Scoped access (recommended — minimizes exposure lifetime)
/// let sum = secret.with_secret(|s| s.iter().sum::<u8>());
/// assert_eq!(sum, 10);
///
/// // Direct access (auditable escape hatch)
/// assert_eq!(secret.expose_secret()[0], 1);
/// ```
pub struct Dynamic<T: ?Sized> {
    inner: Box<T>,
}

impl<T: ?Sized> Dynamic<T> {
    /// Creates a new [`Dynamic<T>`] by boxing the provided value.
    ///
    /// Accepts any type `U` that can be converted into `Box<T>`. This provides
    /// excellent ergonomics for common secret types:
    ///
    /// - Owned `T` (when `T: Sized`) → automatically boxed
    /// - `Vec<u8>` → `Dynamic<Vec<u8>>`
    /// - `String` → `Dynamic<String>`
    /// - An existing `Box<T>`
    ///
    /// When the `zeroize` feature is enabled (default), the inner memory is
    /// automatically zeroized on drop.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// use secure_gate::Dynamic;
    ///
    /// # #[cfg(feature = "alloc")]
    /// {
    ///     // String → Dynamic<String>
    ///     let password: Dynamic<String> = Dynamic::new("hunter2".to_owned());
    ///
    ///     // Vec<u8> → Dynamic<Vec<u8>>
    ///     let key: Dynamic<Vec<u8>> = Dynamic::new(vec![0u8; 32]);
    ///
    ///     // Already a Box
    ///     let boxed = Box::new([1u8; 16]);
    ///     let secret: Dynamic<[u8; 16]> = Dynamic::new(boxed);
    /// }
    /// ```
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

// From impls for Dynamic types
impl<T: ?Sized> From<Box<T>> for Dynamic<T> {
    /// Converts a `Box<T>` into a [`Dynamic<T>`] secret.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// use secure_gate::Dynamic;
    ///
    /// # #[cfg(feature = "alloc")]
    /// {
    /// let boxed = Box::new(vec![1, 2, 3]);
    /// let secret: Dynamic<Vec<u8>> = boxed.into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self { inner: boxed }
    }
}

impl From<&[u8]> for Dynamic<Vec<u8>> {
    /// Converts a byte slice into a [`Dynamic<Vec<u8>>`] secret.
    ///
    /// Copies the slice into a new vector.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// use secure_gate::Dynamic;
    ///
    /// # #[cfg(feature = "alloc")]
    /// {
    /// let slice: &[u8] = &[1, 2, 3, 4];
    /// let secret: Dynamic<Vec<u8>> = slice.into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

impl From<&str> for Dynamic<String> {
    /// Converts a string slice into a [`Dynamic<String>`] secret.
    ///
    /// Copies the string into a new `String`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// use secure_gate::Dynamic;
    ///
    /// # #[cfg(feature = "alloc")]
    /// {
    /// let s = "secret";
    /// let secret: Dynamic<String> = s.into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(input: &str) -> Self {
        Self::new(input.to_string())
    }
}

impl<T: 'static> From<T> for Dynamic<T> {
    /// Converts a value into a [`Dynamic<T>`] secret by boxing it.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// use secure_gate::Dynamic;
    ///
    /// # #[cfg(feature = "alloc")]
    /// {
    /// let value = vec![1, 2, 3];
    /// let secret: Dynamic<Vec<u8>> = value.into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(value: T) -> Self {
        Self {
            inner: Box::new(value),
        }
    }
}

/// Ergonomic encoding helpers for `Dynamic<Vec<u8>>`.
///
/// These methods forward the encoding traits internally via `with_secret`,
/// giving a clean API without breaking the no-[`core::ops::Deref`] rule.
impl Dynamic<Vec<u8>> {
    /// Encodes the secret as a lowercase hexadecimal string.
    ///
    /// *Requires feature `encoding-hex`.*
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Dynamic;
    ///
    /// let key: Dynamic<Vec<u8>> = Dynamic::new(vec![0xde, 0xad, 0xbe, 0xef]);
    /// assert_eq!(key.to_hex(), "deadbeef");
    /// ```
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_hex())
    }

    /// Encodes the secret as an uppercase hexadecimal string.
    ///
    /// *Requires feature `encoding-hex`.*
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Dynamic;
    ///
    /// let key: Dynamic<Vec<u8>> = Dynamic::new(vec![0xde, 0xad, 0xbe, 0xef]);
    /// assert_eq!(key.to_hex_upper(), "DEADBEEF");
    /// ```
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex_upper(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_hex_upper())
    }

    /// Encodes the secret as a base64url string (URL-safe, no padding).
    ///
    /// *Requires feature `encoding-base64`.*
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Dynamic;
    ///
    /// let data: Dynamic<Vec<u8>> = Dynamic::new(vec![0xff, 0x00, 0xaa]);
    /// assert_eq!(data.to_base64url(), "_wCq");
    /// ```
    #[cfg(feature = "encoding-base64")]
    #[inline]
    pub fn to_base64url(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_base64url())
    }

    /// Encodes the secret as a Bech32 string (BIP-173) with the given HRP.
    ///
    /// *Requires feature `encoding-bech32`.*
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Dynamic;
    ///
    /// let data: Dynamic<Vec<u8>> = Dynamic::new(vec![0x00, 0x01]);
    /// let encoded = data.to_bech32("key");
    /// assert!(encoded.starts_with("key1"));
    /// ```
    #[cfg(feature = "encoding-bech32")]
    #[inline]
    pub fn to_bech32(&self, hrp: &str) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_bech32(hrp))
    }

    /// Encodes the secret as a Bech32m string (BIP-350) with the given HRP.
    ///
    /// *Requires feature `encoding-bech32m`.*
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Dynamic;
    ///
    /// let data: Dynamic<Vec<u8>> = Dynamic::new(vec![0x00, 0x01]);
    /// let encoded = data.to_bech32m("key");
    /// assert!(encoded.starts_with("key1"));
    /// ```
    #[cfg(feature = "encoding-bech32m")]
    #[inline]
    pub fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_bech32m(hrp))
    }
}

impl Dynamic<String> {
    /// Returns the inner string as `&str` via scoped access.
    ///
    /// Useful when an API needs a `&str` but you want to keep the `Dynamic<String>`
    /// wrapper for the rest of its lifetime (avoids long-lived `expose_secret`).
    #[inline]
    pub fn as_str(&self) -> &str {
        self.expose_secret().as_str() // ← uses expose_secret (correct lifetime)
    }
}

/// Explicit access to immutable [`Dynamic<String>`] contents.
impl crate::ExposeSecret for Dynamic<String> {
    type Inner = String;

    /// Provides scoped (recommended) immutable access to the inner `String`.
    ///
    /// The closure receives a reference that cannot escape — minimizing the
    /// lifetime of the exposed secret.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// let secret: Dynamic<String> = Dynamic::new("hello".to_string());
    /// let len = secret.with_secret(|s| s.len());
    /// assert_eq!(len, 5);
    /// ```
    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&String) -> R,
    {
        f(&self.inner)
    }

    /// Returns a direct (auditable) immutable reference to the inner `String`.
    ///
    /// Long-lived `expose_secret()` references can defeat scoping — prefer
    /// `with_secret` in application code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// let secret: Dynamic<String> = Dynamic::new("my-key".to_owned());
    /// // FFI example (auditable escape hatch):
    /// // unsafe { c_fn(secret.expose_secret().as_ptr(), secret.len()); }
    /// let _ = secret.expose_secret();
    /// ```
    #[inline(always)]
    fn expose_secret(&self) -> &String {
        &self.inner
    }

    /// Returns the length of the inner `String` in bytes.
    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Explicit access to immutable [`Dynamic<Vec<T>>`] contents.
impl<T> crate::ExposeSecret for Dynamic<Vec<T>> {
    type Inner = Vec<T>;

    /// Provides scoped (recommended) immutable access to the inner `Vec<T>`.
    ///
    /// The closure receives a reference that cannot escape — minimizing the
    /// lifetime of the exposed secret.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3]);
    /// let sum = secret.with_secret(|s| s.iter().sum::<u8>());
    /// assert_eq!(sum, 6);
    /// ```
    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Vec<T>) -> R,
    {
        f(&self.inner)
    }

    /// Returns a direct (auditable) immutable reference to the inner `Vec<T>`.
    ///
    /// Long-lived `expose_secret()` references can defeat scoping — prefer
    /// `with_secret` in application code.
    #[inline(always)]
    fn expose_secret(&self) -> &Vec<T> {
        &self.inner
    }

    /// Returns the length of the inner `Vec<T>` in bytes (`len * size_of::<T>()`).
    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len() * core::mem::size_of::<T>()
    }
}

/// Explicit access to mutable [`Dynamic<String>`] contents.
impl crate::ExposeSecretMut for Dynamic<String> {
    /// Provides scoped (recommended) mutable access to the inner `String`.
    ///
    /// The closure receives a `&mut` reference that cannot escape — minimizing
    /// the mutable exposure window.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ExposeSecretMut, ExposeSecret};
    ///
    /// let mut secret: Dynamic<String> = Dynamic::new("hello".to_string());
    /// secret.with_secret_mut(|s| s.push('!'));
    /// assert_eq!(secret.expose_secret().as_str(), "hello!");
    /// ```
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut String) -> R,
    {
        f(&mut self.inner)
    }

    /// Returns a direct (auditable) mutable reference to the inner `String`.
    ///
    /// Long-lived mutable references can defeat scoping — prefer `with_secret_mut`.
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut String {
        &mut self.inner
    }
}

/// Explicit access to mutable [`Dynamic<Vec<T>>`] contents.
impl<T> crate::ExposeSecretMut for Dynamic<Vec<T>> {
    /// Provides scoped (recommended) mutable access to the inner `Vec<T>`.
    ///
    /// The closure receives a `&mut` reference that cannot escape — minimizing
    /// the mutable exposure window.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ExposeSecretMut, ExposeSecret};
    ///
    /// let mut secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3]);
    /// secret.with_secret_mut(|v| v.push(4));
    /// assert_eq!(secret.expose_secret().len(), 4);
    /// ```
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Vec<T>) -> R,
    {
        f(&mut self.inner)
    }

    /// Returns a direct (auditable) mutable reference to the inner `Vec<T>`.
    ///
    /// Long-lived mutable references can defeat scoping — prefer `with_secret_mut`.
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut Vec<T> {
        &mut self.inner
    }
}

// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Creates a [`Dynamic<Vec<u8>>`] filled with cryptographically secure random bytes.
    ///
    /// *Requires feature `rand`.*
    ///
    /// Uses `OsRng` (the operating system's CSPRNG) for entropy.
    ///
    /// # Panics
    ///
    /// Panics on RNG failure — standard for high-assurance crypto code.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// let key: Dynamic<Vec<u8>> = Dynamic::from_random(32);
    /// assert_eq!(key.len(), 32);
    /// ```
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
    /// Parses a hexadecimal string into a heap-allocated secret.
    ///
    /// *Requires feature `encoding-hex`.*
    ///
    /// # Errors
    ///
    /// - [`crate::error::HexError::InvalidHex`] — `s` contains non-hex characters.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// let secret = Dynamic::try_from_hex("deadbeef")?;
    /// secret.with_secret(|b| assert_eq!(b, &[0xde, 0xad, 0xbe, 0xef]));
    ///
    /// assert!(Dynamic::try_from_hex("xyz").is_err()); // invalid chars
    /// # Ok::<(), secure_gate::HexError>(())
    /// ```
    pub fn try_from_hex(s: &str) -> Result<Self, crate::error::HexError> {
        let bytes = s.try_from_hex()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "encoding-base64")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Parses a base64url string into a heap-allocated secret.
    ///
    /// *Requires feature `encoding-base64`.*
    ///
    /// # Errors
    ///
    /// - [`crate::error::Base64Error::InvalidBase64`] — invalid base64url characters.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// // "AQIDBA" decodes to [1, 2, 3, 4]
    /// let secret = Dynamic::try_from_base64url("AQIDBA")?;
    /// secret.with_secret(|b| assert_eq!(b, &[1, 2, 3, 4]));
    ///
    /// assert!(Dynamic::try_from_base64url("!!!").is_err()); // invalid chars
    /// # Ok::<(), secure_gate::Base64Error>(())
    /// ```
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        let bytes = s.try_from_base64url()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "encoding-bech32")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Parses a Bech32 (BIP-173) string into a heap-allocated secret, discarding the HRP.
    ///
    /// *Requires feature `encoding-bech32`.*
    ///
    /// # Errors
    ///
    /// - [`crate::error::Bech32Error::InvalidHrp`] — malformed HRP.
    /// - [`crate::error::Bech32Error::ConversionFailed`] — bit-conversion failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// let original: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3, 4]);
    /// let encoded = original.to_bech32("test");
    /// let decoded = Dynamic::try_from_bech32(&encoded)?;
    /// decoded.with_secret(|b| assert_eq!(b, &[1, 2, 3, 4]));
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    pub fn try_from_bech32(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "encoding-bech32m")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Parses a Bech32m (BIP-350) string into a heap-allocated secret, discarding the HRP.
    ///
    /// *Requires feature `encoding-bech32m`.*
    ///
    /// # Errors
    ///
    /// - [`crate::error::Bech32Error::InvalidHrp`] — malformed HRP.
    /// - [`crate::error::Bech32Error::ConversionFailed`] — bit-conversion failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// let original: Dynamic<Vec<u8>> = Dynamic::new(vec![0xde, 0xad, 0xbe, 0xef]);
    /// let encoded = original.to_bech32m("key");
    /// let decoded = Dynamic::try_from_bech32m(&encoded)?;
    /// decoded.with_secret(|b| assert_eq!(b, &[0xde, 0xad, 0xbe, 0xef]));
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    pub fn try_from_bech32m(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32m()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "ct-eq")]
/// Constant-time equality for [`Dynamic<T>`] where `T` implements [`crate::ConstantTimeEq`].
impl<T: ?Sized> crate::ConstantTimeEq for Dynamic<T>
where
    T: crate::ConstantTimeEq,
{
    /// Compares two [`Dynamic<T>`] instances in constant time.
    ///
    /// *Requires feature `ct-eq`.* `==` is deliberately not implemented on secret
    /// wrappers — always use `ct_eq` to prevent timing side-channel attacks.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ConstantTimeEq};
    ///
    /// let a: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3]);
    /// let b: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3]);
    /// let c: Dynamic<Vec<u8>> = Dynamic::new(vec![9u8, 2, 3]);
    /// assert!(a.ct_eq(&b));
    /// assert!(!a.ct_eq(&c));
    /// ```
    fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "ct-eq")]
impl Dynamic<Vec<u8>> {
    /// Compares two [`Dynamic<Vec<u8>>`] instances in constant time.
    ///
    /// Compares two `Dynamic<Vec<u8>>` instances in constant time.
    ///
    /// *Requires feature `ct-eq`.* The only safe way to compare heap-secret byte
    /// vectors — `==` is deliberately not implemented.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Dynamic;
    ///
    /// let a: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8; 32]);
    /// let b: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8; 32]);
    /// let c: Dynamic<Vec<u8>> = Dynamic::new(vec![2u8; 32]);
    /// assert!(a.ct_eq(&b));
    /// assert!(!a.ct_eq(&c));
    /// ```
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.inner.as_slice().ct_eq(other.inner.as_slice())
    }
}

#[cfg(feature = "ct-eq-hash")]
/// Probabilistic constant-time equality for [`Dynamic<T>`] using BLAKE3 hash.
impl<T> crate::ConstantTimeEqExt for Dynamic<T>
where
    T: AsRef<[u8]> + crate::ConstantTimeEq + ?Sized,
{
    /// Returns the length of the secret in bytes.
    fn len(&self) -> usize {
        (*self.inner).as_ref().len()
    }

    /// Compares using keyed BLAKE3 hashing — recommended for large secrets.
    ///
    /// *Requires feature `ct-eq-hash`.* Collision probability is 2⁻²⁵⁶ per comparison.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Dynamic, ConstantTimeEqExt};
    ///
    /// let a: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8; 1000]);
    /// let b: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8; 1000]);
    /// let c: Dynamic<Vec<u8>> = Dynamic::new(vec![2u8; 1000]);
    /// assert!(a.ct_eq_hash(&b));
    /// assert!(!a.ct_eq_hash(&c));
    /// ```
    fn ct_eq_hash(&self, other: &Self) -> bool {
        crate::traits::ct_eq_hash_bytes((*self.inner).as_ref(), (*other.inner).as_ref())
    }
    // ct_eq_auto uses default impl
}

// Redacted Debug implementation
/// Debug implementation that redacts secret contents.
///
/// Always prints `[REDACTED]` to prevent accidental leaks.
impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(feature = "cloneable")]
/// Clone implementation for [`Dynamic<T>`] where `T` is cloneable.
///
/// Requires `cloneable` feature.
impl<T: crate::CloneableSecret> Clone for Dynamic<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

#[cfg(feature = "serde-serialize")]
/// Serde serialization for [`Dynamic<T>`] where `T` is serializable.
///
/// Requires `serde-serialize` feature. Note: serialization exposes the secret.
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
/// Serde deserialization for [`Dynamic<String>`].
///
/// Requires `serde-deserialize` feature.
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
/// Serde deserialization for [`Dynamic<Vec<u8>>`].
///
/// Requires `serde-deserialize` feature.
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
/// Zeroize implementation for [`Dynamic<T>`] where `T` implements `Zeroize`.
///
/// Wipes the entire allocation on drop. Requires `zeroize` feature.
impl<T: ?Sized + zeroize::Zeroize> zeroize::Zeroize for Dynamic<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Zeroize on drop integration
#[cfg(feature = "zeroize")]
/// Automatically zeroizes on drop for [`Dynamic<T>`] where `T` implements `Zeroize`.
///
/// Requires `zeroize` feature.
impl<T: ?Sized + zeroize::Zeroize> zeroize::ZeroizeOnDrop for Dynamic<T> {}
