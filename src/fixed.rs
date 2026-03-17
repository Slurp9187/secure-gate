//! Stack-allocated wrapper for fixed-size secrets.
//!
//! Provides [`Fixed<T>`], a zero-cost wrapper enforcing explicit access to sensitive data.
//! Treat secrets as radioactive — minimize exposure surface.
//!
//! # Features
//!
//! - **Core**: Always available — basic wrapping and explicit exposure
//! - **Zeroization**: With `zeroize` — wipes memory on drop
//! - **Random Generation**: With `rand` — generate secure random bytes via `from_random()`
//! - **Encoding/Decoding**: With `encoding-*` — hex, base64url, bech32, bech32m support
//! - **Constant-Time Eq**: With `ct-eq` or `ct-eq-hash` — secure comparisons
//! - **Serde**: With `serde-*` — serialize/deserialize (exposes secrets; use with care)
//! - **Cloneable**: With `cloneable` — clone where inner type allows
//!
//! # Examples
//!
//! Basic usage (always available):
//!
//! ```rust
//! use secure_gate::{Fixed, ExposeSecret};
//!
//! let secret = Fixed::new([1u8, 2, 3, 4]);
//!
//! // Scoped access (recommended — minimizes exposure lifetime)
//! let sum = secret.with_secret(|arr| arr.iter().sum::<u8>());
//! assert_eq!(sum, 10);
//!
//! // Direct access (auditable escape hatch)
//! assert_eq!(secret.expose_secret()[0], 1);
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

/// Zero-cost stack-allocated wrapper for fixed-size secrets.
///
/// Always available, no feature dependencies. Suitable for keys, nonces, tokens,
/// and any secret whose size is known at compile time.
///
/// No `Deref`, `AsRef`, or `Copy` by default — all access requires
/// [`expose_secret()`](ExposeSecret::expose_secret) (direct, auditable) or
/// [`with_secret()`](ExposeSecret::with_secret) (scoped, recommended).
/// `Debug` always prints `[REDACTED]`. When `zeroize` is enabled, the full
/// allocation is wiped on drop. Performance indistinguishable from raw arrays;
/// see [ZERO_COST_WRAPPERS.md](https://github.com/Slurp9187/secure-gate/blob/main/ZERO_COST_WRAPPERS.md).
///
/// # Examples
///
/// Basic construction and access:
///
/// ```rust
/// use secure_gate::{Fixed, ExposeSecret};
///
/// let secret = Fixed::new([42u8; 4]);
///
/// // Scoped access (recommended — minimizes exposure lifetime)
/// let sum = secret.with_secret(|bytes| bytes.iter().sum::<u8>());
/// assert_eq!(sum, 42 * 4);
///
/// // Direct access (auditable escape hatch)
/// assert_eq!(secret.expose_secret()[0], 42);
/// ```
///
/// With macro alias:
///
/// ```rust
/// use secure_gate::{fixed_alias, Fixed, ExposeSecret};
///
/// fixed_alias!(pub ApiKey, 32, "32-byte API key.");
/// let key: ApiKey = [0u8; 32].into();
/// key.with_secret(|b| assert_eq!(b.len(), 32));
/// ```
pub struct Fixed<T> {
    inner: T,
}

impl<T> Fixed<T> {
    /// Creates a new [`Fixed<T>`] by wrapping a value.
    ///
    /// Zero-cost and `const`-friendly constructor.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// const SECRET: Fixed<u32> = Fixed::new(42);
    /// let arr_secret = Fixed::new([1u8, 2, 3, 4]);
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

/// Ergonomic encoding helpers for `Fixed<[u8; N]>`.
///
/// These methods forward the encoding traits internally via `with_secret`,
/// giving a clean API without breaking the no-[`core::ops::Deref`] rule.
impl<const N: usize> Fixed<[u8; N]> {
    /// Encodes the secret as a lowercase hexadecimal string.
    ///
    /// *Requires feature `encoding-hex`.*
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// let key: Fixed<[u8; 4]> = Fixed::new([0xde, 0xad, 0xbe, 0xef]);
    /// assert_eq!(key.to_hex(), "deadbeef");
    /// ```
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_hex())
    }

    /// Encodes the secret as an uppercase hexadecimal string.
    ///
    /// *Requires feature `encoding-hex`.*
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// let key: Fixed<[u8; 4]> = Fixed::new([0xde, 0xad, 0xbe, 0xef]);
    /// assert_eq!(key.to_hex_upper(), "DEADBEEF");
    /// ```
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex_upper(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_hex_upper())
    }

    /// Encodes the secret as a base64url string (URL-safe, no padding).
    ///
    /// *Requires feature `encoding-base64`.*
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// let key: Fixed<[u8; 3]> = Fixed::new([0xff, 0x00, 0xaa]);
    /// assert_eq!(key.to_base64url(), "_wCq");
    /// ```
    #[cfg(feature = "encoding-base64")]
    #[inline]
    pub fn to_base64url(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_base64url())
    }

    /// Encodes the secret as a Bech32 string (BIP-173) with the given HRP.
    ///
    /// *Requires feature `encoding-bech32`.*
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// let key: Fixed<[u8; 2]> = Fixed::new([0x00, 0x01]);
    /// let encoded = key.to_bech32("key");
    /// assert!(encoded.starts_with("key1"));
    /// ```
    #[cfg(feature = "encoding-bech32")]
    #[inline]
    pub fn to_bech32(&self, hrp: &str) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_bech32(hrp))
    }

    /// Encodes the secret as a Bech32m string (BIP-350) with the given HRP.
    ///
    /// *Requires feature `encoding-bech32m`.*
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// let key: Fixed<[u8; 2]> = Fixed::new([0x00, 0x01]);
    /// let encoded = key.to_bech32m("key");
    /// assert!(encoded.starts_with("key1"));
    /// ```
    #[cfg(feature = "encoding-bech32m")]
    #[inline]
    pub fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_bech32m(hrp))
    }
}

/// Explicit access to immutable [`Fixed<[T; N]>`] contents.
impl<const N: usize, T> ExposeSecret for Fixed<[T; N]> {
    type Inner = [T; N];

    /// Provides scoped (recommended) immutable access to the inner array.
    ///
    /// The closure receives a reference that cannot escape — minimizing the
    /// lifetime of the exposed secret. Prefer this over [`expose_secret`](Self::expose_secret).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// let secret = Fixed::new([1u8, 2, 3, 4]);
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

    /// Returns a direct (auditable) immutable reference to the inner array.
    ///
    /// Long-lived `expose_secret()` references can defeat scoping — prefer
    /// [`with_secret`](Self::with_secret) in application code. Use this only when
    /// a long-lived reference is unavoidable, e.g. FFI or third-party APIs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// let secret = Fixed::new([1u8, 2, 3, 4]);
    ///
    /// // FFI example (auditable escape hatch):
    /// // unsafe { c_function(secret.expose_secret().as_ptr(), secret.len()); }
    /// let _ = secret.expose_secret();
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
    /// Provides scoped (recommended) mutable access to the inner array.
    ///
    /// The closure receives a `&mut` reference that cannot escape — minimizing
    /// the mutable exposure window. Prefer this over [`expose_secret_mut`](Self::expose_secret_mut).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecretMut, ExposeSecret};
    ///
    /// let mut secret = Fixed::new([1u8, 2, 3, 4]);
    /// secret.with_secret_mut(|arr| arr[0] = 42);
    /// assert_eq!(secret.expose_secret()[0], 42);
    /// ```
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut [T; N]) -> R,
    {
        f(&mut self.inner)
    }

    /// Returns a direct (auditable) mutable reference to the inner array.
    ///
    /// Long-lived mutable references can defeat scoping — prefer
    /// [`with_secret_mut`](Self::with_secret_mut) in application code.
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut [T; N] {
        &mut self.inner
    }
}

// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Creates a [`Fixed<[u8; N]>`] filled with cryptographically secure random bytes.
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
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// let key: Fixed<[u8; 32]> = Fixed::from_random();
    /// assert_eq!(key.len(), 32);
    /// ```
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
    /// Parses a hexadecimal string into a fixed-size secret.
    ///
    /// *Requires feature `encoding-hex`.*
    ///
    /// The decoded byte count must exactly equal `N`.
    ///
    /// # Errors
    ///
    /// - [`crate::error::HexError::InvalidHex`] — `hex` contains non-hex characters.
    /// - [`crate::error::HexError::InvalidLength`] — decoded byte count ≠ `N`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// type Key = Fixed<[u8; 4]>;
    ///
    /// let key = Key::try_from_hex("deadbeef")?;
    /// key.with_secret(|b| assert_eq!(b, &[0xde, 0xad, 0xbe, 0xef]));
    ///
    /// assert!(Key::try_from_hex("xyz").is_err());   // invalid chars
    /// assert!(Key::try_from_hex("ff").is_err());    // wrong length
    /// # Ok::<(), secure_gate::HexError>(())
    /// ```
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
    /// Parses a base64url string into a fixed-size secret.
    ///
    /// *Requires feature `encoding-base64`.*
    ///
    /// The decoded byte count must exactly equal `N`.
    ///
    /// # Errors
    ///
    /// - [`crate::error::Base64Error::InvalidBase64`] — invalid base64url characters.
    /// - [`crate::error::Base64Error::InvalidLength`] — decoded byte count ≠ `N`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// // "AQID" decodes to [1, 2, 3]
    /// let key = Fixed::<[u8; 3]>::try_from_base64url("AQID")?;
    /// key.with_secret(|b| assert_eq!(b, &[1, 2, 3]));
    ///
    /// assert!(Fixed::<[u8; 3]>::try_from_base64url("!!!").is_err()); // invalid chars
    /// assert!(Fixed::<[u8; 3]>::try_from_base64url("AQIDBA").is_err()); // wrong length
    /// # Ok::<(), secure_gate::Base64Error>(())
    /// ```
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
    /// Parses a Bech32 (BIP-173) string into a fixed-size secret, discarding the HRP.
    ///
    /// *Requires feature `encoding-bech32`.*
    ///
    /// The decoded byte count must exactly equal `N`.
    ///
    /// # Errors
    ///
    /// - [`crate::error::Bech32Error::InvalidHrp`] — malformed HRP.
    /// - [`crate::error::Bech32Error::InvalidLength`] — decoded byte count ≠ `N`.
    /// - [`crate::error::Bech32Error::ConversionFailed`] — bit-conversion failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// let original: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    /// let encoded = original.to_bech32("test");
    /// let decoded = Fixed::<[u8; 4]>::try_from_bech32(&encoded)?;
    /// decoded.with_secret(|b| assert_eq!(b, &[1, 2, 3, 4]));
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
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
    /// Parses a Bech32m (BIP-350) string into a fixed-size secret, discarding the HRP.
    ///
    /// *Requires feature `encoding-bech32m`.*
    ///
    /// The decoded byte count must exactly equal `N`.
    ///
    /// # Errors
    ///
    /// - [`crate::error::Bech32Error::InvalidHrp`] — malformed HRP.
    /// - [`crate::error::Bech32Error::InvalidLength`] — decoded byte count ≠ `N`.
    /// - [`crate::error::Bech32Error::ConversionFailed`] — bit-conversion failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// let original: Fixed<[u8; 4]> = Fixed::new([0xde, 0xad, 0xbe, 0xef]);
    /// let encoded = original.to_bech32m("key");
    /// let decoded = Fixed::<[u8; 4]>::try_from_bech32m(&encoded)?;
    /// decoded.with_secret(|b| assert_eq!(b, &[0xde, 0xad, 0xbe, 0xef]));
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
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
    /// *Requires feature `ct-eq`.* `==` is deliberately not implemented on secret
    /// wrappers — always use `ct_eq` to prevent timing side-channel attacks.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ConstantTimeEq};
    ///
    /// let a = Fixed::new([1u8, 2, 3]);
    /// let b = Fixed::new([1u8, 2, 3]);
    /// let c = Fixed::new([9u8, 2, 3]);
    /// assert!(a.ct_eq(&b));
    /// assert!(!a.ct_eq(&c));
    /// ```
    fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "ct-eq")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Compares two [`Fixed<[u8; N]>`] instances in constant time.
    ///
    /// Compares two `Fixed<[u8; N]>` instances in constant time.
    ///
    /// *Requires feature `ct-eq`.* The only safe way to compare byte-array secrets —
    /// `==` is deliberately not implemented.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// let a = Fixed::new([1u8; 32]);
    /// let b = Fixed::new([1u8; 32]);
    /// let c = Fixed::new([2u8; 32]);
    /// assert!(a.ct_eq(&b));
    /// assert!(!a.ct_eq(&c));
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

    /// Compares using keyed BLAKE3 hashing — recommended for large secrets.
    ///
    /// *Requires feature `ct-eq-hash`.* Collision probability is 2⁻²⁵⁶ per comparison.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ConstantTimeEqExt};
    ///
    /// let a = Fixed::new([1u8; 100]);
    /// let b = Fixed::new([1u8; 100]);
    /// let c = Fixed::new([2u8; 100]);
    /// assert!(a.ct_eq_hash(&b));
    /// assert!(!a.ct_eq_hash(&c));
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
/// *Requires feature `serde-deserialize`.*
///
/// # Implementation Notes
///
/// This implementation uses `std::fmt::Formatter` in the `Visitor::expecting` method.
/// That pulls in `std` even when only `alloc` is present, so `serde-deserialize`
/// is currently incompatible with pure `no_std` builds. The impl itself is correct
/// and must not be changed to avoid breaking this constraint.
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
