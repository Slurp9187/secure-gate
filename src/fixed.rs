//! Secure stack-allocated secrets for fixed-size data.
//!
//! This module provides [`Fixed<T>`], a zero-cost wrapper around sized types `T` designed for
//! storing fixed secrets like byte arrays or primitives. It enforces explicit access patterns
//! to minimize accidental exposure and integrates with security features like zeroization.
//!
//! # Features
//!
//! - **Core**: Always available (no dependencies). Provides basic wrapping and explicit exposure.
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
//! - No implicit `Copy` — cloning requires explicit `.clone()`.
//!
//! # Examples
//!
//! Basic usage:
//!
//! ```rust
//! use secure_gate::{Fixed, ExposeSecret};
//!
//! let secret = Fixed::new([1, 2, 3]);
//! let sum: u8 = secret.with_secret(|arr| arr.iter().sum());
//! assert_eq!(sum, 6);
//! ```
//!
//! With random generation (requires `rand`):
//!
//! ```rust
//! # #[cfg(feature = "rand")]
//! {
//! use secure_gate::{Fixed, ExposeSecret};
//!
//! let key = Fixed::<[u8; 32]>::from_random();
//! assert_eq!(key.len(), 32);
//! }
//! ```

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

use crate::ExposeSecretMut; // ← Add this too, for consistency with ExposeSecret

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

/// Zero-cost stack-allocated secure secret wrapper for fixed-size data.
///
/// Wraps sized secrets like byte arrays or primitives.
/// Always available, no dependencies.
///
/// # Security
///
/// - No `Deref` or `AsRef` — prevents accidental access.
/// - No implicit `Copy` — cloning requires explicit `.clone()`.
/// - `Debug` always redacts contents.
/// - Zeroizes on drop with `zeroize` feature.
/// - Explicit access via [`ExposeSecret`] and [`ExposeSecretMut`].
///
/// # Examples
///
/// ```rust
/// use secure_gate::{Fixed, ExposeSecret};
///
/// let secret = Fixed::new([42u8; 4]);
/// let first = secret.expose_secret()[0];
/// assert_eq!(first, 42);
/// ```
///
/// With type alias:
///
/// ```rust
/// use secure_gate::{fixed_alias, Fixed, ExposeSecret};
///
/// fixed_alias!(Key32, 32);
/// let key: Key32 = Fixed::new([0u8; 32]);
/// assert_eq!(key.len(), 32);
/// ```
///
/// With zeroize:
///
/// ```rust
/// # #[cfg(feature = "zeroize")]
/// use secure_gate::Fixed;
///
/// # #[cfg(feature = "zeroize")]
/// {
/// let secret = Fixed::new([1, 2, 3, 4]);
/// drop(secret); // wiped
/// # }
/// ```
pub struct Fixed<T> {
    inner: T,
}

impl<T> Fixed<T> {
    /// Creates a new [`Fixed<T>`] by wrapping a value.
    ///
    /// Zero-cost and const-friendly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// const SECRET: Fixed<u32> = Fixed::new(42);
    /// let dynamic = Fixed::new([1, 2, 3, 4]);
    /// ```
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed { inner: value }
    }
}

impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    /// Converts a byte array into a [`Fixed<[u8; N]>`] secret.
    ///
    /// Zero-cost conversion.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// let key: Fixed<[u8; 4]> = [1, 2, 3, 4].into();
    /// ```
    #[inline(always)]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

// Fallible conversion from byte slice.
impl<const N: usize> core::convert::TryFrom<&[u8]> for Fixed<[u8; N]> {
    type Error = crate::error::FromSliceError;

    /// Attempts to create a [`Fixed<[u8; N]>`] from a byte slice.
    ///
    /// The slice must be exactly `N` bytes long.
    /// In debug builds, panics with details on mismatch.
    /// In release builds, returns generic error to prevent leaks.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// let slice = &[1u8, 2, 3, 4];
    /// let key = Fixed::<[u8; 4]>::try_from(slice as &[u8]).unwrap();
    /// ```
    ///
    /// # Panics
    ///
    /// Panics in debug builds if lengths don't match.
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != N {
            #[cfg(debug_assertions)]
            panic!(
                "Fixed<{}> from_slice: expected exactly {} bytes, got {}",
                N,
                N,
                slice.len()
            );
            #[cfg(not(debug_assertions))]
            return Err(crate::error::FromSliceError::LengthMismatch);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Ok(Self::new(arr))
    }
}

/// Ergonomic encoding and access helpers for byte arrays.
///
/// These forward the encoding traits (`ToHex`, `ToBase64Url`, `ToBech32`, etc.)
/// while still enforcing `with_secret` access. This gives you a nice API
/// without breaking the no-`Deref` security rule.
impl<const N: usize> Fixed<[u8; N]> {
    /// Encodes the secret as lowercase hexadecimal.
    ///
    /// Requires the `encoding-hex` feature.
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_hex())
    }

    /// Encodes the secret as uppercase hexadecimal.
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex_upper(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_hex_upper())
    }

    /// Encodes the secret as base64url (URL-safe, no padding).
    ///
    /// Requires the `encoding-base64` feature.
    #[cfg(feature = "encoding-base64")]
    #[inline]
    pub fn to_base64url(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_base64url())
    }

    /// Encodes the secret as Bech32 (BIP-173) with the given HRP.
    ///
    /// Requires the `encoding-bech32` feature.
    #[cfg(feature = "encoding-bech32")]
    #[inline]
    pub fn to_bech32(&self, hrp: &str) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_bech32(hrp))
    }

    /// Encodes the secret as Bech32m (BIP-350) with the given HRP.
    ///
    /// Requires the `encoding-bech32m` feature.
    #[cfg(feature = "encoding-bech32m")]
    #[inline]
    pub fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_bech32m(hrp))
    }
}

/// Explicit access to immutable [`Fixed<[T; N]>`] contents.
impl<const N: usize, T> ExposeSecret for Fixed<[T; N]> {
    type Inner = [T; N];

    /// Provides scoped immutable access to the inner array.
    ///
    /// This is the preferred way to access the secret, as it limits the lifetime
    /// of the reference to the closure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// let secret = Fixed::new([1, 2, 3, 4]);
    /// let sum = secret.with_secret(|arr| arr.iter().sum::<u8>());
    /// assert_eq!(sum, 10);
    /// ```
    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[T; N]) -> R,
    {
        f(&self.inner)
    }

    /// Returns an immutable reference to the inner array.
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
    /// use secure_gate::Fixed;
    ///
    /// let secret = Fixed::new([1, 2, 3, 4]);
    ///
    /// // Typical FFI use case
    /// // unsafe {
    /// //     c_library_function(secret.expose_secret().as_ptr(), secret.len());
    /// // }
    /// ```
    #[inline(always)]
    fn expose_secret(&self) -> &[T; N] {
        &self.inner
    }

    /// Returns the length of the secret in bytes.
    #[inline(always)]
    fn len(&self) -> usize {
        N * core::mem::size_of::<T>()
    }
}

/// Explicit access to mutable [`Fixed<[T; N]>`] contents.
impl<const N: usize, T> ExposeSecretMut for Fixed<[T; N]> {
    /// Provides scoped mutable access to the inner array.
    ///
    /// This is the preferred way to mutate the secret, as it limits the lifetime
    /// of the reference to the closure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecretMut};
    ///
    /// let mut secret = Fixed::new([1, 2, 3, 4]);
    /// secret.with_secret_mut(|arr| arr[0] = 42);
    /// ```
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut [T; N]) -> R,
    {
        f(&mut self.inner)
    }

    /// Returns a mutable reference to the inner array.
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
    fn expose_secret_mut(&mut self) -> &mut [T; N] {
        &mut self.inner
    }
}

// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Creates a [`Fixed<[u8; N]>`] filled with random bytes from the system RNG.
    ///
    /// Uses `OsRng` for cryptographically secure entropy. Panics on failure.
    /// Requires `rand` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "rand")]
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// # #[cfg(feature = "rand")]
    /// {
    /// let random: Fixed<[u8; 32]> = Fixed::from_random();
    /// assert_eq!(random.len(), 32);
    /// # }
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails.
    #[inline]
    pub fn from_random() -> Self {
        let mut bytes = [0u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failure is a program error");
        Self::from(bytes)
    }
}

// Decoding constructors — only available with encoding features.
#[cfg(feature = "encoding-hex")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decodes a hex string into a [`Fixed<[u8; N]>`] secret.
    ///
    /// Decoded bytes must exactly match array length `N`.
    /// Requires `encoding-hex` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "encoding-hex")]
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// # #[cfg(feature = "encoding-hex")]
    /// {
    /// let secret: Fixed<[u8; 4]> = Fixed::try_from_hex("01234567").unwrap();
    /// assert_eq!(secret.len(), 4);
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::HexError`] on invalid hex or length mismatches.
    pub fn try_from_hex(hex: &str) -> Result<Self, crate::error::HexError> {
        let bytes = hex.try_from_hex()?;
        if bytes.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::HexError::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::HexError::InvalidLength);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }
}

#[cfg(feature = "encoding-base64")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decodes a base64url string into a [`Fixed<[u8; N]>`] secret.
    ///
    /// Decoded bytes must exactly match array length `N`.
    /// Requires `encoding-base64` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "encoding-base64")]
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// # #[cfg(feature = "encoding-base64")]
    /// {
    /// let secret: Fixed<[u8; 3]> = Fixed::try_from_base64url("QkNE").unwrap();
    /// assert_eq!(secret.expose_secret()[0], 0x42);
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Base64Error`] on invalid base64 or length mismatches.
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        let bytes: Vec<u8> = s.try_from_base64url()?;
        if bytes.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::Base64Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::Base64Error::InvalidLength);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }
}

#[cfg(feature = "encoding-bech32")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decodes a bech32 string into a [`Fixed<[u8; N]>`] secret, discarding the HRP.
    ///
    /// Decoded bytes must exactly match array length `N`.
    /// Requires `encoding-bech32` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "encoding-bech32")]
    /// use secure_gate::{Fixed, ToBech32, ExposeSecret};
    ///
    /// # #[cfg(feature = "encoding-bech32")]
    /// {
    /// let original: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    /// let bech32: String = original.with_secret(|s: &[u8; 4]| s.to_bech32("test"));
    /// let decoded = Fixed::<[u8; 4]>::try_from_bech32(&bech32).unwrap();
    /// // HRP discarded
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Bech32Error`] on invalid bech32.
    pub fn try_from_bech32(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes): (_, Vec<u8>) = s.try_from_bech32()?;
        if bytes.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::Bech32Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::Bech32Error::InvalidLength);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }
}

#[cfg(feature = "encoding-bech32m")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decodes a bech32m string into a [`Fixed<[u8; N]>`] secret, discarding the HRP.
    ///
    /// Decoded bytes must exactly match array length `N`.
    /// Requires `encoding-bech32m` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "encoding-bech32m")]
    /// use secure_gate::Fixed;
    ///
    /// # #[cfg(feature = "encoding-bech32m")]
    /// {
    /// let bech32m = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    /// let secret = Fixed::<[u8; 33]>::try_from_bech32m(bech32m).unwrap();
    /// // HRP discarded
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Bech32Error`] on invalid bech32m.
    pub fn try_from_bech32m(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes): (_, Vec<u8>) = s.try_from_bech32m()?;
        if bytes.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::Bech32Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::Bech32Error::InvalidLength);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }
}

#[cfg(feature = "ct-eq")]
/// Constant-time equality for [`Fixed<T>`] where `T` implements [`crate::ConstantTimeEq`].
impl<T> crate::ConstantTimeEq for Fixed<T>
where
    T: crate::ConstantTimeEq,
{
    /// Compares two [`Fixed<T>`] instances in constant time.
    ///
    /// Requires `ct-eq` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "ct-eq")]
    /// use secure_gate::{Fixed, ConstantTimeEq};
    ///
    /// # #[cfg(feature = "ct-eq")]
    /// {
    /// let a = Fixed::new([1, 2, 3]);
    /// let b = Fixed::new([1, 2, 3]);
    /// assert!(a.ct_eq(&b));
    /// # }
    /// ```
    fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "ct-eq")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Compares two [`Fixed<[u8; N]>`] instances in constant time.
    ///
    /// The only safe way to compare fixed-size secrets. Requires `ct-eq` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "ct-eq")]
    /// use secure_gate::Fixed;
    ///
    /// # #[cfg(feature = "ct-eq")]
    /// {
    /// let a = Fixed::new([1u8; 32]);
    /// let b = Fixed::new([1u8; 32]);
    /// assert!(a.ct_eq(&b));
    /// # }
    /// ```
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "ct-eq-hash")]
/// Probabilistic constant-time equality for [`Fixed<T>`] using BLAKE3 hash.
impl<T> crate::ConstantTimeEqExt for Fixed<T>
where
    T: AsRef<[u8]> + crate::ConstantTimeEq,
{
    /// Returns the length of the secret in bytes.
    fn len(&self) -> usize {
        self.inner.as_ref().len()
    }

    /// Compares using BLAKE3 hash for large secrets.
    ///
    /// Requires `ct-eq-hash` feature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "ct-eq-hash")]
    /// use secure_gate::{Fixed, ConstantTimeEqExt};
    ///
    /// # #[cfg(feature = "ct-eq-hash")]
    /// {
    /// let a = Fixed::new([1; 100]);
    /// let b = Fixed::new([1; 100]);
    /// assert!(a.ct_eq_hash(&b));
    /// # }
    /// ```
    fn ct_eq_hash(&self, other: &Self) -> bool {
        crate::traits::ct_eq_hash_bytes(self.inner.as_ref(), other.inner.as_ref())
    }
}

// Redacted Debug implementation
/// Debug implementation that redacts secret contents.
///
/// Always prints `[REDACTED]` to prevent accidental leaks.
impl<T> core::fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(feature = "cloneable")]
/// Clone implementation for [`Fixed<T>`] where `T` is cloneable.
///
/// Requires `cloneable` feature.
impl<T: crate::CloneableSecret> Clone for Fixed<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

#[cfg(feature = "serde-serialize")]
/// Serde serialization for [`Fixed<T>`] where `T` is serializable.
///
/// Requires `serde-serialize` feature. Note: serialization exposes the secret.
impl<T> serde::Serialize for Fixed<T>
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

/// Custom Serde deserialization for [`Fixed<[u8; N]>`] from byte sequences.
///
/// Requires `serde-deserialize` feature.
#[cfg(feature = "serde-deserialize")]
impl<'de, const N: usize> serde::Deserialize<'de> for Fixed<[u8; N]> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Visitor;
        use std::fmt;
        struct FixedVisitor<const M: usize>;
        impl<'de, const M: usize> Visitor<'de> for FixedVisitor<M> {
            type Value = Fixed<[u8; M]>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a byte array of length {}", M)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = alloc::vec::Vec::with_capacity(M);
                while let Some(value) = seq.next_element()? {
                    vec.push(value);
                }
                if vec.len() != M {
                    return Err(serde::de::Error::invalid_length(
                        vec.len(),
                        &M.to_string().as_str(),
                    ));
                }
                let mut arr = [0u8; M];
                arr.copy_from_slice(&vec);
                Ok(Fixed::new(arr))
            }
        }
        deserializer.deserialize_seq(FixedVisitor::<N>)
    }
}

// Zeroize integration
#[cfg(feature = "zeroize")]
/// Zeroize implementation for [`Fixed<T>`] where `T` implements `Zeroize`.
///
/// Wipes the secret on drop. Requires `zeroize` feature.
impl<T: zeroize::Zeroize> zeroize::Zeroize for Fixed<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Zeroize on drop integration
#[cfg(feature = "zeroize")]
/// Automatically zeroizes [`Fixed<T>`] on drop where `T` implements `Zeroize`.
///
/// Requires `zeroize` feature.
impl<T: zeroize::Zeroize> zeroize::ZeroizeOnDrop for Fixed<T> {}
