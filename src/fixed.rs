#[cfg(feature = "rand")]
use rand::TryRngCore;

/// Local implementation of bit conversion for Bech32, since bech32 crate doesn't expose it in v0.11.
#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
fn convert_bits(
    from: u8,
    to: u8,
    pad: bool,
    data: &[u8],
) -> Result<(alloc::vec::Vec<u8>, usize), ()> {
    if !(1..=8).contains(&from) || !(1..=8).contains(&to) {
        return Err(());
    }
    let mut acc = 0u64;
    let mut bits = 0u8;
    let mut ret = alloc::vec::Vec::new();
    let maxv = (1u64 << to) - 1;
    let _max_acc = (1u64 << (from + to - 1)) - 1;
    for &v in data {
        if ((v as u32) >> from) != 0 {
            return Err(());
        }
        acc = (acc << from) | (v as u64);
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(());
    }
    Ok((ret, bits as usize))
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
use base64::{engine::general_purpose, Engine};

/// Helper function to try decoding a string as bech32, hex, or base64 in priority order.
#[cfg(feature = "serde-deserialize")]
fn try_decode(s: &str) -> Result<alloc::vec::Vec<u8>, crate::DecodingError> {
    #[cfg(feature = "encoding-bech32")]
    if let Ok((_, data)) = ::bech32::decode(s) {
        let (converted, _) =
            convert_bits(5, 8, false, &data).map_err(|_| crate::DecodingError::InvalidBech32)?;
        return Ok(converted);
    }
    #[cfg(feature = "encoding-hex")]
    if let Ok(data) = ::hex::decode(s) {
        return Ok(data);
    }

    #[cfg(feature = "encoding-base64")]
    if let Ok(data) = Engine::decode(&general_purpose::URL_SAFE_NO_PAD, s) {
        return Ok(data);
    }
    Err(crate::DecodingError::InvalidEncoding)
}

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
pub struct Fixed<T> {
    inner: T,
}

impl<T> Fixed<T> {
    /// Wrap a value in a `Fixed` secret.
    ///
    /// This is zero-cost and const-friendly.
    ///
    /// Wrap a value in a Fixed secret.
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

#[cfg(feature = "cloneable")]
impl<T: crate::CloneableType> Clone for Fixed<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

#[cfg(feature = "serde-serialize")]
impl<T: crate::SerializableType> serde::Serialize for Fixed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
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

#[cfg(feature = "ct-eq")]
impl<T> crate::ConstantTimeEq for Fixed<T>
where
    T: crate::ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "hash-eq")]
impl<T> crate::HashEq for Fixed<T>
where
    T: AsRef<[u8]>,
{
    fn hash_eq(&self, other: &Self) -> bool {
        #[cfg(feature = "rand")]
        {
            use once_cell::sync::Lazy;
            use rand::{rngs::OsRng, TryRngCore};
            static HASH_EQ_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
                let mut key = [0u8; 32];
                let mut rng = OsRng;
                rng.try_fill_bytes(&mut key).unwrap();
                key
            });
            let mut self_hasher = blake3::Hasher::new_keyed(&HASH_EQ_KEY);
            let mut other_hasher = blake3::Hasher::new_keyed(&HASH_EQ_KEY);
            self_hasher.update(self.inner.as_ref());
            other_hasher.update(other.inner.as_ref());
            use crate::ConstantTimeEq;
            self_hasher
                .finalize()
                .as_bytes()
                .ct_eq(other_hasher.finalize().as_bytes())
        }
        #[cfg(not(feature = "rand"))]
        {
            let self_hash = blake3::hash(self.inner.as_ref());
            let other_hash = blake3::hash(other.inner.as_ref());
            use crate::ConstantTimeEq;
            self_hash.as_bytes().ct_eq(other_hash.as_bytes())
        }
    }
}

/// # Byte-array specific helpers
impl<const N: usize> Fixed<[u8; N]> {}

// Fallible conversion from byte slice.
impl<const N: usize> core::convert::TryFrom<&[u8]> for Fixed<[u8; N]> {
    type Error = crate::error::FromSliceError;

    /// Attempt to create a `Fixed` from a byte slice, returning an error on length mismatch.
    ///
    /// This is the safe alternative to panicking conversions.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// let slice: &[u8] = &[1u8, 2, 3, 4];
    /// let key: Result<Fixed<[u8; 4]>, _> = slice.try_into();
    /// assert!(key.is_ok());
    ///
    /// let short_slice: &[u8] = &[1u8, 2];
    /// let fail: Result<Fixed<[u8; 4]>, _> = short_slice.try_into();
    /// assert!(fail.is_err());
    /// ```
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != N {
            return Err(crate::error::FromSliceError::LengthMismatch {
                expected: N,
                got: slice.len(),
            });
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Ok(Self::new(arr))
    }
}

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

/// Custom serde deserialization for byte arrays with auto-detection of hex/base64/bech32 strings.
#[cfg(feature = "serde-deserialize")]
impl<'de, const N: usize> serde::Deserialize<'de> for Fixed<[u8; N]> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor};
        use std::fmt;

        struct FixedVisitor<const M: usize>;

        impl<'de, const M: usize> Visitor<'de> for FixedVisitor<M> {
            type Value = Fixed<[u8; M]>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "a hex/base64/bech32 string or byte array of length {}",
                    M
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bytes = try_decode(v).map_err(E::custom)?;
                if bytes.len() != M {
                    return Err(E::invalid_length(bytes.len(), &M.to_string().as_str()));
                }
                let mut arr = [0u8; M];
                arr.copy_from_slice(&bytes);
                Ok(Fixed::new(arr))
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

        deserializer.deserialize_any(FixedVisitor::<N>)
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
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failure is a program error");
        Self::from(bytes)
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

// Optional Hash impl for collections (use HashEq for explicit equality checks)
#[cfg(feature = "hash-eq")]
impl<T: AsRef<[u8]>> core::hash::Hash for Fixed<T> {
    /// WARNING: Using Fixed in HashMap/HashSet enables implicit equality via hash collisions.
    /// This is probabilistic and NOT cryptographically secure. Prefer HashEq::hash_eq() for secrets.
    /// Rate-limit or avoid in untrusted contexts due to DoS potential.
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        use blake3::hash;
        let hash_bytes = *hash(self.inner.as_ref()).as_bytes();
        hash_bytes.hash(state);
    }
}

// Redacted Debug implementation
impl<T> core::fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// Serde deserialization for generic Fixed<T> (simple delegation)

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
