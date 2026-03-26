//! Stack-allocated wrapper for fixed-size secrets.
//!
//! Provides [`Fixed<T>`], a zero-cost wrapper enforcing explicit access to sensitive data.
//! Treat secrets as radioactive — minimize exposure surface.
//!
//! Inner type **must implement `Zeroize`** for automatic zeroization on drop.
//!
//! # Examples
//!
//! ```rust
//! use secure_gate::{Fixed, RevealSecret};
//!
//! let secret = Fixed::new([1u8, 2, 3, 4]);
//! let sum = secret.with_secret(|arr| arr.iter().sum::<u8>());
//! assert_eq!(sum, 10);
//! ```

use crate::RevealSecret;
use crate::RevealSecretMut;

#[cfg(feature = "encoding-base64")]
use crate::traits::encoding::base64_url::ToBase64Url;
#[cfg(feature = "encoding-hex")]
use crate::traits::encoding::hex::ToHex;

#[cfg(feature = "rand")]
use rand::{TryCryptoRng, TryRng, rngs::SysRng};
use zeroize::Zeroize;

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
/// Always available. Inner type **must implement `Zeroize`** for automatic zeroization on drop.
///
/// No `Deref`, `AsRef`, or `Copy` by default — all access requires
/// [`expose_secret()`](RevealSecret::expose_secret) or
/// [`with_secret()`](RevealSecret::with_secret) (scoped, preferred).
/// For construction of `Fixed<[u8; N]>`, [`new_with`](Fixed::new_with) is the
/// matching scoped constructor — it writes directly into the wrapper's storage
/// and avoids any intermediate stack copy. [`new(value)`](Fixed::new) remains
/// available as the ergonomic default.
/// `Debug` always prints `[REDACTED]`. Performance indistinguishable from raw arrays.
pub struct Fixed<T: zeroize::Zeroize> {
    inner: T,
}

impl<T: zeroize::Zeroize> Fixed<T> {
    /// Creates a new [`Fixed<T>`] by wrapping a value.
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed { inner: value }
    }
}

impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

impl<const N: usize> core::convert::TryFrom<&[u8]> for Fixed<[u8; N]> {
    type Error = crate::error::FromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::FromSliceError::InvalidLength {
                actual: slice.len(),
                expected: N,
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::FromSliceError::InvalidLength);
        }
        Ok(Self::new_with(|arr| arr.copy_from_slice(slice)))
    }
}

/// Construction and ergonomic encoding helpers for `Fixed<[u8; N]>`.
impl<const N: usize> Fixed<[u8; N]> {
    /// Writes directly into the wrapper's storage via a user-supplied closure,
    /// eliminating the intermediate stack copy that [`new`](Self::new) may produce.
    ///
    /// The array is zero-initialized before the closure runs. Prefer this over
    /// [`new(value)`](Self::new) when minimizing stack residue matters
    /// (long-lived keys, high-assurance environments).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// let secret = Fixed::<[u8; 4]>::new_with(|arr| arr.fill(0xAB));
    /// ```
    #[inline(always)]
    pub fn new_with<F>(f: F) -> Self
    where
        F: FnOnce(&mut [u8; N]),
    {
        let mut this = Self { inner: [0u8; N] };
        f(&mut this.inner);
        this
    }

    /// Encodes the secret bytes as a lowercase hex string.
    ///
    /// Delegates to [`ToHex::to_hex`](crate::ToHex::to_hex) on the inner `[u8; N]`.
    /// Requires the `encoding-hex` feature.
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_hex())
    }

    /// Encodes the secret bytes as an uppercase hex string.
    ///
    /// Delegates to [`ToHex::to_hex_upper`](crate::ToHex::to_hex_upper) on the inner `[u8; N]`.
    /// Requires the `encoding-hex` feature.
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex_upper(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_hex_upper())
    }

    /// Encodes the secret bytes as an unpadded Base64url string.
    ///
    /// Delegates to [`ToBase64Url::to_base64url`](crate::ToBase64Url::to_base64url) on the inner `[u8; N]`.
    /// Requires the `encoding-base64` feature.
    #[cfg(feature = "encoding-base64")]
    #[inline]
    pub fn to_base64url(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_base64url())
    }
}

/// Explicit access to immutable [`Fixed<[T; N]>`] contents.
impl<const N: usize, T: zeroize::Zeroize> RevealSecret for Fixed<[T; N]> {
    type Inner = [T; N];

    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[T; N]) -> R,
    {
        f(&self.inner)
    }

    #[inline(always)]
    fn expose_secret(&self) -> &[T; N] {
        &self.inner
    }

    #[inline(always)]
    fn len(&self) -> usize {
        N * core::mem::size_of::<T>()
    }
}

/// Explicit access to mutable [`Fixed<[T; N]>`] contents.
impl<const N: usize, T: zeroize::Zeroize> RevealSecretMut for Fixed<[T; N]> {
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut [T; N]) -> R,
    {
        f(&mut self.inner)
    }

    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut [T; N] {
        &mut self.inner
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Fills a new `[u8; N]` with cryptographically secure random bytes and wraps it.
    ///
    /// Uses the system RNG ([`SysRng`](rand::rngs::SysRng)). Requires the `rand` feature.
    /// Heap-free and works in `no_std` / `no_alloc` builds.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails to provide bytes ([`TryRng::try_fill_bytes`](rand::TryRng::try_fill_bytes)
    /// returns `Err`). This is treated as a fatal environment error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "rand")]
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// # #[cfg(feature = "rand")]
    /// # {
    /// let key: Fixed<[u8; 32]> = Fixed::from_random();
    /// assert_eq!(key.len(), 32);
    /// # }
    /// ```
    #[inline]
    pub fn from_random() -> Self {
        Self::new_with(|arr| {
            SysRng
                .try_fill_bytes(arr)
                .expect("SysRng failure is a program error");
        })
    }

    /// Fills a new `[u8; N]` from `rng` and wraps it.
    ///
    /// Accepts any [`TryCryptoRng`](rand::TryCryptoRng) + [`TryRng`](rand::TryRng) — for example,
    /// a seeded [`StdRng`](rand::rngs::StdRng) for deterministic tests. Requires the `rand`
    /// feature. Heap-free.
    ///
    /// # Errors
    ///
    /// Returns `R::Error` if [`try_fill_bytes`](rand::TryRng::try_fill_bytes) fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    /// use secure_gate::Fixed;
    ///
    /// let mut rng = StdRng::from_seed([1u8; 32]);
    /// let key: Fixed<[u8; 16]> = Fixed::from_rng(&mut rng).expect("rng fill");
    /// # }
    /// ```
    #[inline]
    pub fn from_rng<R: TryRng + TryCryptoRng>(rng: &mut R) -> Result<Self, R::Error> {
        let mut result = Ok(());
        let this = Self::new_with(|arr| {
            result = rng.try_fill_bytes(arr);
        });
        result.map(|_| this) // on Err, `this` drops → zeroizes any partial fill
    }
}

#[cfg(feature = "encoding-hex")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decodes a lowercase hex string into `Fixed<[u8; N]>`.
    ///
    /// The decoded bytes are held in a `Zeroizing<Vec<u8>>` until copied onto
    /// the stack array, so the temporary heap buffer is zeroed even if a panic
    /// occurs mid-flight.
    ///
    /// # Errors
    ///
    /// Returns `HexError::InvalidLength` if the decoded length does not equal `N`,
    /// or a parse error if the input is not valid hex.
    ///
    /// # Note
    ///
    /// Unlike [`Dynamic::try_from_hex`](crate::Dynamic::try_from_hex), the secret
    /// lives on the stack inside a `[u8; N]`. Stack residue behaviour after the
    /// `Fixed` is dropped and zeroized is discussed in `SECURITY.md`.
    pub fn try_from_hex(hex: &str) -> Result<Self, crate::error::HexError> {
        let bytes = zeroize::Zeroizing::new(hex.try_from_hex()?);
        if bytes.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::HexError::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::HexError::InvalidLength);
        }
        Ok(Self::new_with(|arr| arr.copy_from_slice(&bytes)))
    }
}

#[cfg(feature = "encoding-base64")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decodes an unpadded Base64url string into `Fixed<[u8; N]>`.
    ///
    /// The decoded bytes are held in a `Zeroizing<Vec<u8>>` until copied onto
    /// the stack array, so the temporary heap buffer is zeroed even if a panic
    /// occurs mid-flight.
    ///
    /// # Errors
    ///
    /// Returns `Base64Error::InvalidLength` if the decoded length does not equal `N`,
    /// or a parse error if the input is not valid Base64url.
    ///
    /// # Note
    ///
    /// Unlike [`Dynamic::try_from_base64url`](crate::Dynamic::try_from_base64url), the
    /// secret lives on the stack inside a `[u8; N]`. Stack residue behaviour after the
    /// `Fixed` is dropped and zeroized is discussed in `SECURITY.md`.
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        let bytes = zeroize::Zeroizing::new(s.try_from_base64url()?);
        if bytes.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::Base64Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::Base64Error::InvalidLength);
        }
        Ok(Self::new_with(|arr| arr.copy_from_slice(&bytes)))
    }
}

#[cfg(feature = "encoding-bech32")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decodes a Bech32 (BIP-173) string into `Fixed<[u8; N]>`.
    ///
    /// # Warning
    ///
    /// The HRP is **not validated** — any HRP will be accepted as long as the checksum
    /// is valid and the payload length equals `N`. For security-critical code where
    /// cross-protocol confusion must be prevented, use [`try_from_bech32`](Self::try_from_bech32).
    pub fn try_from_bech32_unchecked(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes_raw) = s.try_from_bech32_unchecked()?;
        let bytes = zeroize::Zeroizing::new(bytes_raw);
        if bytes.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::Bech32Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::Bech32Error::InvalidLength);
        }
        Ok(Self::new_with(|arr| arr.copy_from_slice(&bytes)))
    }

    /// Decodes a Bech32 (BIP-173) string into `Fixed<[u8; N]>`, validating that the HRP
    /// matches `expected_hrp` (case-insensitive).
    ///
    /// Prefer this over [`try_from_bech32_unchecked`](Self::try_from_bech32_unchecked) in
    /// security-critical code to prevent cross-protocol confusion attacks.
    pub fn try_from_bech32(s: &str, expected_hrp: &str) -> Result<Self, crate::error::Bech32Error> {
        let bytes_raw = s.try_from_bech32(expected_hrp)?;
        let bytes = zeroize::Zeroizing::new(bytes_raw);
        if bytes.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::Bech32Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::Bech32Error::InvalidLength);
        }
        Ok(Self::new_with(|arr| arr.copy_from_slice(&bytes)))
    }
}

#[cfg(feature = "encoding-bech32m")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decodes a Bech32m (BIP-350) string into `Fixed<[u8; N]>`.
    ///
    /// # Warning
    ///
    /// The HRP is **not validated** — any HRP will be accepted as long as the checksum
    /// is valid and the payload length equals `N`. For security-critical code where
    /// cross-protocol confusion must be prevented, use [`try_from_bech32m`](Self::try_from_bech32m).
    pub fn try_from_bech32m_unchecked(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes_raw) = s.try_from_bech32m_unchecked()?;
        let bytes = zeroize::Zeroizing::new(bytes_raw);
        if bytes.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::Bech32Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::Bech32Error::InvalidLength);
        }
        Ok(Self::new_with(|arr| arr.copy_from_slice(&bytes)))
    }

    /// Decodes a Bech32m (BIP-350) string into `Fixed<[u8; N]>`, validating that the HRP
    /// matches `expected_hrp` (case-insensitive).
    ///
    /// Prefer this over [`try_from_bech32m_unchecked`](Self::try_from_bech32m_unchecked) in
    /// security-critical code to prevent cross-protocol confusion attacks.
    pub fn try_from_bech32m(s: &str, expected_hrp: &str) -> Result<Self, crate::error::Bech32Error> {
        let bytes_raw = s.try_from_bech32m(expected_hrp)?;
        let bytes = zeroize::Zeroizing::new(bytes_raw);
        if bytes.len() != N {
            #[cfg(debug_assertions)]
            return Err(crate::error::Bech32Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
            #[cfg(not(debug_assertions))]
            return Err(crate::error::Bech32Error::InvalidLength);
        }
        Ok(Self::new_with(|arr| arr.copy_from_slice(&bytes)))
    }
}

#[cfg(feature = "ct-eq")]
impl<T: zeroize::Zeroize> crate::ConstantTimeEq for Fixed<T>
where
    T: crate::ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

impl<T: zeroize::Zeroize> core::fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(feature = "cloneable")]
impl<T: zeroize::Zeroize + crate::CloneableSecret> Clone for Fixed<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

#[cfg(feature = "serde-serialize")]
impl<T: zeroize::Zeroize + crate::SerializableSecret> serde::Serialize for Fixed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de, const N: usize> serde::Deserialize<'de> for Fixed<[u8; N]> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;
        use serde::de::Visitor;
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
                let mut vec: zeroize::Zeroizing<alloc::vec::Vec<u8>> =
                    zeroize::Zeroizing::new(alloc::vec::Vec::with_capacity(M));
                while let Some(value) = seq.next_element()? {
                    vec.push(value);
                }
                if vec.len() != M {
                    #[cfg(debug_assertions)]
                    return Err(serde::de::Error::invalid_length(
                        vec.len(),
                        &M.to_string().as_str(),
                    ));
                    #[cfg(not(debug_assertions))]
                    return Err(serde::de::Error::custom("decoded length mismatch"));
                }
                Ok(Fixed::new_with(|arr| arr.copy_from_slice(&vec)))
            }
        }
        deserializer.deserialize_seq(FixedVisitor::<N>)
    }
}

// Zeroize integration — now always present
impl<T: zeroize::Zeroize> zeroize::Zeroize for Fixed<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: zeroize::Zeroize> Drop for Fixed<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: zeroize::Zeroize> zeroize::ZeroizeOnDrop for Fixed<T> {}
