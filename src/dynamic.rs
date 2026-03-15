//! Secure heap-allocated secrets for variable-length data.
//!
//! This module provides [`Dynamic<T>`], a zero-cost wrapper around `Box<T>` designed for
//! storing secrets like API keys, passwords, or cryptographic material. It enforces explicit
//! access patterns to minimize accidental exposure and integrates with security features like
//! zeroization.
//!
//! # Features
//!
//! - **Core**: Requires `alloc`. Provides basic wrapping and explicit exposure.
//! - **Zeroization**: With `zeroize` (default), wipes memory on drop.
//! - **Random Generation**: With `rand`, generate secure random bytes.
//! - **Encoding/Decoding**: With `encoding-*` features, decode from hex, base64url, bech32, etc.
//! - **Constant-Time Eq**: With `ct-eq` or `ct-eq-hash`, secure comparisons.
//! - **Serde**: With `serde-*`, serialize/deserialize (note: serialization exposes secrets).
//! - **Cloneable**: With `cloneable`, clone secrets where inner type allows.
//!
//! # Security Considerations
//!
//! - No implicit deref or borrowing—use [`ExposeSecret`] or [`ExposeSecretMut`] traits.
//! - Debug redacts contents to `[REDACTED]`.
//! - Prefer scoped access with `with_secret` over `expose_secret` to limit lifetime.
//! - For large secrets, use hash-based constant-time eq to avoid timing attacks.
//!
//! # Examples
//!
//! Basic usage:
//!
//! ```rust
//! # #[cfg(feature = "alloc")]
//! {
//! use secure_gate::{Dynamic, ExposeSecret};
//!
//! let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3]);
//! let sum: u8 = secret.with_secret(|s| s.iter().sum());
//! assert_eq!(sum, 6);
//! }
//! ```
//!
//! With random generation (requires `rand`):
//!
//! ```rust
//! # #[cfg(all(feature = "alloc", feature = "rand"))]
//! {
//! use secure_gate::{Dynamic, ExposeSecret};
//!
//! let key = Dynamic::from_random(32);
//! assert_eq!(key.len(), 32);
//! }
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

/// Zero-cost heap-allocated secure secret wrapper for variable-length data.
///
/// Wraps `Box<T>` with enforced explicit exposure. Requires `alloc` feature.
/// Suitable for dynamic secrets like `String` or `Vec<u8>`.
///
/// # Security
///
/// - No `Deref` or `AsRef` — prevents accidental access.
/// - `Debug` always redacts contents.
/// - Zeroizes entire allocation on drop (including spare capacity) with `zeroize` feature.
/// - Explicit access via [`ExposeSecret`] and [`ExposeSecretMut`].
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "alloc")]
/// {
/// use secure_gate::{Dynamic, ExposeSecret};
///
/// let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
/// let len = ExposeSecret::len(&secret);
/// assert_eq!(len, 4);
///
/// let sum: u8 = secret.with_secret(|s| s.iter().sum());
/// assert_eq!(sum, 10);
/// # }
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

/// Ergonomic encoding and access helpers for common heap types.
///
/// These forward the encoding traits while still enforcing `with_secret` access.
impl Dynamic<Vec<u8>> {
    /// Encodes the secret as lowercase hexadecimal.
    ///
    /// Requires the `encoding-hex` feature.
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_hex())
    }

    /// Encodes the secret as uppercase hexadecimal.
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex_upper(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_hex_upper())
    }

    /// Encodes the secret as base64url (URL-safe, no padding).
    ///
    /// Requires the `encoding-base64` feature.
    #[cfg(feature = "encoding-base64")]
    #[inline]
    pub fn to_base64url(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_base64url())
    }

    /// Encodes the secret as Bech32 (BIP-173) with the given HRP.
    ///
    /// Requires the `encoding-bech32` feature.
    #[cfg(feature = "encoding-bech32")]
    #[inline]
    pub fn to_bech32(&self, hrp: &str) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_bech32(hrp))
    }

    /// Encodes the secret as Bech32m (BIP-350) with the given HRP.
    ///
    /// Requires the `encoding-bech32m` feature.
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

    /// Provides scoped immutable access to the inner `String`.
    ///
    /// This is the preferred way to access the secret, as it limits the lifetime
    /// of the reference to the closure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// # #[cfg(feature = "alloc")]
    /// {
    /// let secret: Dynamic<String> = Dynamic::new("hello".to_string());
    /// let len = secret.with_secret(|s| s.len());
    /// assert_eq!(len, 5);
    /// # }
    /// ```
    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&String) -> R,
    {
        f(&self.inner)
    }

    /// Returns an immutable reference to the inner `String`.
    ///
    /// # Security
    ///
    /// **Prefer [`with_secret`]** in most code — it limits exposure to the closure scope,
    /// reducing the chance of accidental leaks.
    ///
    /// Use `expose_secret` only when you truly need a long-lived reference, such as:
    ///
    /// - **FFI** calls to C libraries (e.g. `as_ptr()` + `len()`)
    /// - Third-party APIs that only accept `&T` directly
    /// - When the reference must outlive a single statement
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// use secure_gate::Dynamic;
    ///
    /// # #[cfg(feature = "alloc")]
    /// {
    /// let secret: Dynamic<String> = Dynamic::new("my-secret-key".to_owned());
    ///
    /// // Typical FFI use case
    /// // unsafe {
    /// //     c_library_function(secret.expose_secret().as_ptr(), secret.len());
    /// // }
    /// }
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

    /// Provides scoped immutable access to the inner `Vec<T>`.
    ///
    /// This is the preferred way to access the secret, as it limits the lifetime
    /// of the reference to the closure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// # #[cfg(feature = "alloc")]
    /// {
    /// let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3]);
    /// let sum = secret.with_secret(|s: &Vec<u8>| s.iter().sum::<u8>());
    /// assert_eq!(sum, 6);
    /// # }
    /// ```
    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Vec<T>) -> R,
    {
        f(&self.inner)
    }

    /// Returns an immutable reference to the inner `Vec<T>`.
    ///
    /// # Security
    ///
    /// **Prefer [`with_secret`]** in most code — it limits exposure to the closure scope,
    /// reducing the chance of accidental leaks.
    ///
    /// Use `expose_secret` only when you truly need a long-lived reference, such as:
    ///
    /// - **FFI** calls to C libraries (e.g. `as_ptr()` + `len()`)
    /// - Third-party APIs that only accept `&T` directly
    /// - When the reference must outlive a single statement
    #[inline(always)]
    fn expose_secret(&self) -> &Vec<T> {
        &self.inner
    }

    /// Returns the length of the inner `Vec<T>` in bytes (len * size_of::<T>()).
    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len() * core::mem::size_of::<T>()
    }
}

/// Explicit access to mutable [`Dynamic<String>`] contents.
impl crate::ExposeSecretMut for Dynamic<String> {
    /// Provides scoped mutable access to the inner `String`.
    ///
    /// This is the preferred way to mutate the secret, as it limits the lifetime
    /// of the reference to the closure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// use secure_gate::{Dynamic, ExposeSecretMut};
    ///
    /// # #[cfg(feature = "alloc")]
    /// {
    /// let mut secret: Dynamic<String> = Dynamic::new("hello".to_string());
    /// secret.with_secret_mut(|s: &mut String| s.push_str(" world"));
    /// # }
    /// ```
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut String) -> R,
    {
        f(&mut self.inner)
    }

    /// Returns a mutable reference to the inner `String`.
    ///
    /// # Security
    ///
    /// **Prefer [`with_secret_mut`]** in most code — it limits exposure to the closure scope,
    /// reducing the chance of accidental leaks.
    ///
    /// Use `expose_secret_mut` only when you truly need a long-lived reference, such as:
    ///
    /// - **FFI** calls to C libraries
    /// - Third-party APIs that only accept `&mut T` directly
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut String {
        &mut self.inner
    }
}

/// Explicit access to mutable [`Dynamic<Vec<T>>`] contents.
impl<T> crate::ExposeSecretMut for Dynamic<Vec<T>> {
    /// Provides scoped mutable access to the inner `Vec<T>`.
    ///
    /// This is the preferred way to mutate the secret, as it limits the lifetime
    /// of the reference to the closure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// use secure_gate::{Dynamic, ExposeSecretMut};
    ///
    /// # #[cfg(feature = "alloc")]
    /// {
    /// let mut secret: Dynamic<Vec<i32>> = Dynamic::new(vec![1, 2, 3]);
    /// secret.with_secret_mut(|v: &mut Vec<i32>| v.push(4));
    /// # }
    /// ```
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Vec<T>) -> R,
    {
        f(&mut self.inner)
    }

    /// Returns a mutable reference to the inner `Vec<T>`.
    ///
    /// # Security
    ///
    /// **Prefer [`with_secret_mut`]** in most code — it limits exposure to the closure scope,
    /// reducing the chance of accidental leaks.
    ///
    /// Use `expose_secret_mut` only when you truly need a long-lived reference, such as:
    ///
    /// - **FFI** calls to C libraries
    /// - Third-party APIs that only accept `&mut T` directly
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut Vec<T> {
        &mut self.inner
    }
}

// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Creates a [`Dynamic<Vec<u8>>`] filled with random bytes from the system RNG.
    ///
    /// Uses `OsRng` for cryptographically secure entropy. Panics on RNG failure.
    /// Requires `rand` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "rand"))]
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// # #[cfg(all(feature = "alloc", feature = "rand"))]
    /// {
    /// let secret = Dynamic::from_random(32);
    /// assert_eq!(secret.len(), 32);
    /// # }
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails.
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
    /// Decodes a hex string into a [`Dynamic<Vec<u8>>`] secret.
    ///
    /// Requires `encoding-hex` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "encoding-hex"))]
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// # #[cfg(all(feature = "alloc", feature = "encoding-hex"))]
    /// {
    /// let secret = Dynamic::try_from_hex("0123456789abcdef").unwrap();
    /// assert_eq!(secret.len(), 8);
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::HexError`] on invalid hex or length mismatches.
    pub fn try_from_hex(s: &str) -> Result<Self, crate::error::HexError> {
        let bytes = s.try_from_hex()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "encoding-base64")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a base64url string into a [`Dynamic<Vec<u8>>`] secret.
    ///
    /// Requires `encoding-base64` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "encoding-base64"))]
    /// use secure_gate::{Dynamic, ExposeSecret};
    ///
    /// # #[cfg(all(feature = "alloc", feature = "encoding-base64"))]
    /// {
    /// let secret = Dynamic::try_from_base64url("AQIDBA").unwrap();
    /// assert_eq!(secret.len(), 4);
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Base64Error`] on invalid base64 or length mismatches.
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        let bytes = s.try_from_base64url()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "encoding-bech32")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a bech32 string into a [`Dynamic<Vec<u8>>`] secret, discarding the HRP.
    ///
    /// Requires `encoding-bech32` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "encoding-bech32"))]
    /// use secure_gate::{Dynamic, ToBech32, ExposeSecret};
    ///
    /// # #[cfg(all(feature = "alloc", feature = "encoding-bech32"))]
    /// {
    /// let original: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3, 4]);
    /// let bech32 = original.with_secret(|s: &Vec<u8>| s.to_bech32("test"));
    /// let decoded = Dynamic::try_from_bech32(&bech32).unwrap();
    /// // HRP discarded, bytes stored
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Bech32Error`] on invalid bech32.
    pub fn try_from_bech32(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32()?;
        Ok(Self::new(bytes))
    }
}

#[cfg(feature = "encoding-bech32m")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Decodes a bech32m string into a [`Dynamic<Vec<u8>>`] secret, discarding the HRP.
    ///
    /// Requires `encoding-bech32m` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "encoding-bech32m"))]
    /// use secure_gate::Dynamic;
    ///
    /// # #[cfg(all(feature = "alloc", feature = "encoding-bech32m"))]
    /// {
    /// let bech32m = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    /// let secret = Dynamic::try_from_bech32m(bech32m).unwrap();
    /// // HRP discarded, bytes stored
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Bech32Error`] on invalid bech32m.
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
    /// Requires `ct-eq` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "ct-eq"))]
    /// use secure_gate::{Dynamic, ConstantTimeEq};
    ///
    /// # #[cfg(all(feature = "alloc", feature = "ct-eq"))]
    /// {
    /// let a: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3]);
    /// let b: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3]);
    /// assert!(a.ct_eq(&b));
    /// # }
    /// ```
    fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "ct-eq")]
impl Dynamic<Vec<u8>> {
    /// Compares two [`Dynamic<Vec<u8>>`] instances in constant time.
    ///
    /// Compares byte contents to prevent timing attacks. Requires `ct-eq` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "ct-eq"))]
    /// use secure_gate::Dynamic;
    ///
    /// # #[cfg(all(feature = "alloc", feature = "ct-eq"))]
    /// {
    /// let a: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8; 1000]);
    /// let b: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8; 1000]);
    /// assert!(a.ct_eq(&b));
    /// # }
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

    /// Compares using BLAKE3 hash for large secrets.
    ///
    /// Requires `ct-eq-hash` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "ct-eq-hash"))]
    /// use secure_gate::{Dynamic, ConstantTimeEqExt};
    ///
    /// # #[cfg(all(feature = "alloc", feature = "ct-eq-hash"))]
    /// {
    /// let a: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8; 1000]);
    /// let b: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8; 1000]);
    /// assert!(a.ct_eq_hash(&b));
    /// # }
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
