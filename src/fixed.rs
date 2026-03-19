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
//! use secure_gate::{Fixed, ExposeSecret};
//!
//! let secret = Fixed::new([1u8, 2, 3, 4]);
//! let sum = secret.with_secret(|arr| arr.iter().sum::<u8>());
//! assert_eq!(sum, 10);
//! ```

use crate::ExposeSecret;
use crate::ExposeSecretMut;

#[cfg(feature = "encoding-base64")]
use crate::traits::encoding::base64_url::ToBase64Url;
#[cfg(feature = "encoding-hex")]
use crate::traits::encoding::hex::ToHex;

#[cfg(feature = "rand")]
use rand::{rngs::OsRng, TryRngCore};
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
/// [`expose_secret()`](ExposeSecret::expose_secret) or
/// [`with_secret()`](ExposeSecret::with_secret) (scoped, recommended).
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
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Ok(Self::new(arr))
    }
}

/// Ergonomic encoding helpers for `Fixed<[u8; N]>`.
impl<const N: usize> Fixed<[u8; N]> {
    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_hex())
    }

    #[cfg(feature = "encoding-hex")]
    #[inline]
    pub fn to_hex_upper(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_hex_upper())
    }

    #[cfg(feature = "encoding-base64")]
    #[inline]
    pub fn to_base64url(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_base64url())
    }
}

/// Explicit access to immutable [`Fixed<[T; N]>`] contents.
impl<const N: usize, T: zeroize::Zeroize> ExposeSecret for Fixed<[T; N]> {
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
impl<const N: usize, T: zeroize::Zeroize> ExposeSecretMut for Fixed<[T; N]> {
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
    #[inline]
    pub fn from_random() -> Self {
        let mut bytes = [0u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failure is a program error");
        Self::from(bytes)
    }
}

#[cfg(feature = "encoding-hex")]
impl<const N: usize> Fixed<[u8; N]> {
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
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }
}

#[cfg(feature = "encoding-base64")]
impl<const N: usize> Fixed<[u8; N]> {
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
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
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
    /// cross-protocol confusion must be prevented, use [`try_from_bech32_expect_hrp`](Self::try_from_bech32_expect_hrp).
    pub fn try_from_bech32(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes_raw) = s.try_from_bech32()?;
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
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }

    /// Decodes a Bech32 (BIP-173) string into `Fixed<[u8; N]>`, validating that the HRP
    /// matches `expected_hrp` (case-insensitive).
    ///
    /// Prefer this over [`try_from_bech32`](Self::try_from_bech32) in security-critical code
    /// to prevent cross-protocol confusion attacks.
    pub fn try_from_bech32_expect_hrp(s: &str, expected_hrp: &str) -> Result<Self, crate::error::Bech32Error> {
        let bytes_raw = s.try_from_bech32_expect_hrp(expected_hrp)?;
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
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
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
    /// cross-protocol confusion must be prevented, use [`try_from_bech32m_expect_hrp`](Self::try_from_bech32m_expect_hrp).
    pub fn try_from_bech32m(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes_raw) = s.try_from_bech32m()?;
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
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }

    /// Decodes a Bech32m (BIP-350) string into `Fixed<[u8; N]>`, validating that the HRP
    /// matches `expected_hrp` (case-insensitive).
    ///
    /// Prefer this over [`try_from_bech32m`](Self::try_from_bech32m) in security-critical code
    /// to prevent cross-protocol confusion attacks.
    pub fn try_from_bech32m_expect_hrp(s: &str, expected_hrp: &str) -> Result<Self, crate::error::Bech32Error> {
        let bytes_raw = s.try_from_bech32m_expect_hrp(expected_hrp)?;
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
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
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

#[cfg(feature = "ct-eq-hash")]
impl<T: zeroize::Zeroize> crate::ConstantTimeEqExt for Fixed<T>
where
    T: AsRef<[u8]> + crate::ConstantTimeEq,
{
    fn len(&self) -> usize {
        self.inner.as_ref().len()
    }

    fn ct_eq_hash(&self, other: &Self) -> bool {
        crate::traits::ct_eq_hash_bytes(self.inner.as_ref(), other.inner.as_ref())
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
                let mut arr = [0u8; M];
                arr.copy_from_slice(&vec);
                Ok(Fixed::new(arr))
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
