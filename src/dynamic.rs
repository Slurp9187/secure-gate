extern crate alloc;

use alloc::boxed::Box;
#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
use base64::{engine::general_purpose, Engine};

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
    if let Ok(data) = general_purpose::URL_SAFE_NO_PAD.decode(s) {
        return Ok(data);
    }

    Err(crate::DecodingError::InvalidEncoding)
}

/// Dynamic-sized heap-allocated secure secret wrapper.
///
/// This is a thin wrapper around `Box<T>` with enforced explicit exposure.
/// Suitable for dynamic-sized secrets like `String` or `Vec<u8>`.
/// The inner field is private, forcing all access through explicit methods.
///
/// Security invariants:
/// - No `Deref` or `AsRef` — prevents silent access.
/// - `Debug` is always redacted.
/// - With `zeroize`, wipes the entire allocation on drop (including spare capacity).
///
/// # Examples
///
/// Basic usage:
/// ```
/// use secure_gate::{Dynamic, ExposeSecret};
/// let secret: Dynamic<String> = "hunter2".into();
/// assert_eq!(secret.expose_secret(), "hunter2");
/// ```
///
/// With already-boxed values:
/// ```
/// use secure_gate::{Dynamic, ExposeSecret};
/// let boxed_secret = Box::new("hunter2".to_string());
/// let secret: Dynamic<String> = boxed_secret.into(); // or Dynamic::from(boxed_secret)
/// assert_eq!(secret.expose_secret(), "hunter2");
/// ```
///
/// Mutable access:
/// ```
/// use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};
/// let mut secret = Dynamic::<String>::new("pass".to_string());
/// secret.expose_secret_mut().push('!');
/// assert_eq!(secret.expose_secret(), "pass!");
/// ```
///
/// With `zeroize` (automatic wipe):
/// With `zeroize` feature (automatic wipe on drop):
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::Dynamic;
/// let secret = Dynamic::<Vec<u8>>::new(vec![1u8; 32]);
/// drop(secret); // heap allocation wiped automatically
/// # }
/// ```
pub struct Dynamic<T: ?Sized> {
    inner: Box<T>,
}

impl<T: ?Sized> Dynamic<T> {
    /// Wrap a value by boxing it.
    ///
    /// Uses `Into<Box<T>>` for flexibility.
    #[inline(always)]
    pub fn new<U>(value: U) -> Self
    where
        U: Into<Box<T>>,
    {
        let inner = value.into();
        Self { inner }
    }
}

#[cfg(feature = "cloneable")]
impl<T: crate::CloneableType> Clone for Dynamic<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

#[cfg(feature = "serde-serialize")]
impl<T: crate::SerializableType> serde::Serialize for Dynamic<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

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

impl<T> crate::ExposeSecret for Dynamic<Vec<T>> {
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

impl<T> crate::ExposeSecretMut for Dynamic<Vec<T>> {
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

#[cfg(feature = "ct-eq")]
impl<T> crate::ConstantTimeEq for Dynamic<T>
where
    T: crate::ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> bool {
        (*self.inner).ct_eq(&*other.inner)
    }
}

#[cfg(feature = "hash-eq")]
impl<T> crate::HashEq for Dynamic<T>
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
            self_hasher.update((*self.inner).as_ref());
            other_hasher.update((*other.inner).as_ref());
            use crate::ConstantTimeEq;
            self_hasher
                .finalize()
                .as_bytes()
                .ct_eq(other_hasher.finalize().as_bytes())
        }
        #[cfg(not(feature = "rand"))]
        {
            let self_hash = blake3::hash((*self.inner).as_ref());
            let other_hash = blake3::hash((*other.inner).as_ref());
            use crate::ConstantTimeEq;
            self_hash.as_bytes().ct_eq(other_hash.as_bytes())
        }
    }
}

/// # Ergonomic helpers for common heap types
impl Dynamic<String> {}
impl<T> Dynamic<Vec<T>> {}

// From impls for Dynamic types
impl<T: ?Sized> From<Box<T>> for Dynamic<T> {
    /// Wrap a boxed value in a [`Dynamic`] secret.
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self { inner: boxed }
    }
}

impl From<&[u8]> for Dynamic<Vec<u8>> {
    /// Wrap a byte slice in a [`Dynamic`] [`Vec<u8>`].
    #[inline(always)]
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

impl From<&str> for Dynamic<String> {
    /// Wrap a string slice in a [`Dynamic`] [`String`].
    #[inline(always)]
    fn from(input: &str) -> Self {
        Self::new(input.to_string())
    }
}

impl<T: 'static> From<T> for Dynamic<T> {
    /// Wrap a value in a [`Dynamic`] secret by boxing it.
    #[inline(always)]
    fn from(value: T) -> Self {
        Self {
            inner: Box::new(value),
        }
    }
}

// Optional Hash impls for collections (use HashEq for explicit equality checks)
#[cfg(feature = "hash-eq")]
impl core::hash::Hash for Dynamic<alloc::vec::Vec<u8>> {
    /// WARNING: Using Dynamic in HashMap/HashSet enables implicit equality via hash collisions.
    /// This is probabilistic and NOT cryptographically secure. Prefer HashEq::hash_eq() for secrets.
    /// Rate-limit or avoid in untrusted contexts due to DoS potential.
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        use blake3::hash;
        let hash_bytes = *hash(self.inner.as_slice()).as_bytes();
        hash_bytes.hash(state);
    }
}

#[cfg(feature = "hash-eq")]
impl core::hash::Hash for Dynamic<alloc::string::String> {
    /// WARNING: Using Dynamic in HashMap/HashSet enables implicit equality via hash collisions.
    /// This is probabilistic and NOT cryptographically secure. Prefer HashEq::hash_eq() for secrets.
    /// Rate-limit or avoid in untrusted contexts due to DoS potential.
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        use blake3::hash;
        let hash_bytes = *hash(self.inner.as_bytes()).as_bytes();
        hash_bytes.hash(state);
    }
}

// Macro-generated implementations
// Constant-time equality for Dynamic types
#[cfg(feature = "ct-eq")]
impl Dynamic<String> {
    /// Constant-time equality comparison.
    ///
    /// Compares the byte contents of two instances in constant time
    /// to prevent timing attacks.
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.inner.as_bytes().ct_eq(other.inner.as_bytes())
    }
}

#[cfg(feature = "ct-eq")]
impl Dynamic<Vec<u8>> {
    /// Constant-time equality comparison.
    ///
    /// Compares the byte contents of two instances in constant time
    /// to prevent timing attacks.
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.inner.as_slice().ct_eq(other.inner.as_slice())
    }
}

// Redacted Debug implementation
impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// Macro-generated constructor implementations
// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Fill with fresh random bytes of the specified length using the System RNG.
    ///
    /// Panics on RNG failure for fail-fast crypto code. Guarantees secure entropy
    /// from system sources.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::{Dynamic, ExposeSecret};
    /// let random: Dynamic<Vec<u8>> = Dynamic::from_random(64);
    /// assert_eq!(random.len(), 64);
    /// # }
    /// ```
    #[inline]
    pub fn from_random(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failure is a program error");
        Self::from(bytes)
    }
}

// Serde deserialization for Dynamic<Vec<u8>> with auto-decoding, and simple delegation for others
#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<alloc::vec::Vec<u8>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use alloc::fmt;
        use serde::de::{self, Visitor};

        struct DynamicVecVisitor;

        impl<'de> Visitor<'de> for DynamicVecVisitor {
            type Value = Dynamic<alloc::vec::Vec<u8>>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a hex/base64/bech32 string or byte vector")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bytes = try_decode(v).map_err(E::custom)?;
                Ok(Dynamic::new(bytes))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(DynamicVecVisitor)
        } else {
            let vec: alloc::vec::Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
            Ok(Dynamic::new(vec))
        }
    }
}

// Serde deserialization for Dynamic<String>
#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<String> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        Ok(Dynamic::new(s))
    }
}

// Zeroize integration
#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::Zeroize for Dynamic<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Zeroize on drop integration
#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::ZeroizeOnDrop for Dynamic<T> {}
