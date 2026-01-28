/// Fixed-size stack-allocated secure secret wrapper.
///
/// This is a zero-cost wrapper for fixed-size secrets like byte arrays or primitives.
/// The inner field is private, forcing all access through explicit methods.
///
/// Security invariants:
/// - No `Deref` or `AsRef` — prevents silent access or borrowing.
/// - No implicit `Copy` — even for `[u8; N]`, duplication must be explicit via `.clone()`.
/// - `Debug` is always redacted.
///
/// # Examples
///
/// Basic usage:
/// ```
/// use secure_gate::{Fixed, ExposeSecret};
/// let secret = Fixed::new([42u8; 1]);
/// assert_eq!(secret.expose_secret()[0], 42);
/// ```
///
/// For byte arrays (most common):
/// ```
/// use secure_gate::{fixed_alias, Fixed, ExposeSecret};
/// fixed_alias!(Aes256Key, 32);
/// let key_bytes = [0x42u8; 32];
/// let key: Aes256Key = Fixed::from(key_bytes);
/// assert_eq!(key.len(), 32);
/// assert_eq!(key.expose_secret()[0], 0x42);
/// ```
///
/// With `zeroize` feature (automatic wipe on drop):
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::Fixed;
/// let mut secret = Fixed::new([1u8, 2, 3]);
/// drop(secret); // stack memory wiped automatically
/// # }
/// ```
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
pub struct Fixed<T> {
    inner: T,
}

impl<T> Fixed<T> {
    /// Wrap a value in a `Fixed` secret.
    ///
    /// This is zero-cost and const-friendly.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// const SECRET: Fixed<u32> = Fixed::new(42);
    /// ```
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed { inner: value }
    }
}

/// # Byte-array specific helpers
impl<const N: usize> Fixed<[u8; N]> {}

impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    /// Wrap a raw byte array in a `Fixed` secret.
    ///
    /// Zero-cost conversion.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
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

    /// Attempt to create a `Fixed` from a byte slice.
    /// In debug builds, panics with detailed information on length mismatch to aid development.
    /// In release builds, returns an error on length mismatch to prevent information leaks.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// let slice: &[u8] = &[1u8, 2, 3, 4];
    /// let key: Result<Fixed<[u8; 4]>, _> = slice.try_into();
    /// assert!(key.is_ok());
    /// ```
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

impl<const N: usize, T> crate::ExposeSecret for Fixed<[T; N]> {
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

impl<const N: usize, T> crate::ExposeSecretMut for Fixed<[T; N]> {
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

// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Generate a secure random instance (panics on failure).
    ///
    /// Fill with fresh random bytes using the System RNG.
    /// Panics on RNG failure for fail-fast crypto code. Guarantees secure entropy
    /// from system sources.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::{Fixed, ExposeSecret};
    /// let random: Fixed<[u8; 32]> = Fixed::from_random();
    /// assert_eq!(random.len(), 32);
    /// # }
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
    /// Decode a hex string into a Fixed secret.
    ///
    /// The decoded bytes must exactly match the array length `N`.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "encoding-hex")]
    /// use secure_gate::{Fixed, ExposeSecret};
    /// let hex_string = "424344"; // 3 bytes
    /// let secret: Fixed<[u8; 3]> = Fixed::try_from_hex(hex_string).unwrap();
    /// assert_eq!(secret.expose_secret()[0], 0x42);
    /// ```
    pub fn try_from_hex(s: &str) -> Result<Self, crate::error::HexError> {
        let bytes: Vec<u8> = s.try_from_hex()?;
        if bytes.len() != N {
            return Err(crate::error::HexError::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }
}

#[cfg(feature = "encoding-base64")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decode a base64url string into a Fixed secret.
    ///
    /// The decoded bytes must exactly match the array length `N`.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "encoding-base64")]
    /// use secure_gate::{Fixed, ExposeSecret};
    /// let b64_string = "QkNE"; // 3 bytes
    /// let secret: Fixed<[u8; 3]> = Fixed::try_from_base64url(b64_string).unwrap();
    /// assert_eq!(secret.expose_secret()[0], 0x42);
    /// ```
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        let bytes: Vec<u8> = s.try_from_base64url()?;
        if bytes.len() != N {
            return Err(crate::error::Base64Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }
}

#[cfg(feature = "encoding-bech32")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decode a bech32 string into a Fixed secret, discarding the HRP.
    ///
    /// The decoded bytes must exactly match the array length `N`.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "encoding-bech32")]
    /// use secure_gate::{Fixed, ExposeSecret, ToBech32};
    /// let original = Fixed::new([1, 2, 3, 4]);
    /// let bech32_string = original.with_secret(|s| s.to_bech32("test"));
    /// let decoded = Fixed::<[u8; 4]>::try_from_bech32(&bech32_string).unwrap();
    /// // HRP "test" is discarded
    /// ```
    pub fn try_from_bech32(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes): (_, Vec<u8>) = s.try_from_bech32()?;
        if bytes.len() != N {
            return Err(crate::error::Bech32Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }
}

#[cfg(feature = "encoding-bech32m")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Decode a bech32m string into a Fixed secret, discarding the HRP.
    ///
    /// The decoded bytes must exactly match the array length `N`.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "encoding-bech32m")]
    /// use secure_gate::Fixed;
    /// // Note: Bech32m strings must be valid Bech32m format
    /// let bech32m_string = "abc1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"; // 32 bytes
    /// let secret: Result<Fixed<[u8; 32]>, _> = Fixed::try_from_bech32m(bech32m_string);
    /// // Returns Result<Fixed<[u8; 32]>, Bech32Error>
    /// ```
    pub fn try_from_bech32m(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes): (_, Vec<u8>) = s.try_from_bech32m()?;
        if bytes.len() != N {
            return Err(crate::error::Bech32Error::InvalidLength {
                expected: N,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self::new(arr))
    }
}

#[cfg(feature = "ct-eq")]
impl<T> crate::ConstantTimeEq for Fixed<T>
where
    T: crate::ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

// Constant-time equality
#[cfg(feature = "ct-eq")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Constant-time equality comparison.
    ///
    /// This is the **only safe way** to compare two fixed-size secrets.
    /// Available only when the `ct-eq` feature is enabled.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "ct-eq")]
    /// # {
    /// use secure_gate::Fixed;
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
impl<T> crate::ConstantTimeEqExt for Fixed<T>
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

// Redacted Debug implementation
impl<T> core::fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(feature = "cloneable")]
impl<T: crate::CloneableSecret> Clone for Fixed<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

#[cfg(feature = "serde-serialize")]
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

/// Custom serde deserialization for byte arrays (direct to sequence).
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
impl<T: zeroize::Zeroize> zeroize::Zeroize for Fixed<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Zeroize on drop integration
#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::ZeroizeOnDrop for Fixed<T> {}
