#[cfg(feature = "alloc")]
extern crate alloc;
use alloc::boxed::Box;

#[cfg(feature = "rand")]
use rand::{rngs::OsRng, TryRngCore};

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
impl<T: ?Sized> crate::ConstantTimeEq for Dynamic<T>
where
    T: crate::ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "ct-eq-hash")]
impl<T> crate::ConstantTimeEqExt for Dynamic<T>
where
    T: AsRef<[u8]> + crate::ConstantTimeEq + ?Sized,
{
    fn len(&self) -> usize {
        (*self.inner).as_ref().len()
    }

    fn ct_eq_hash(&self, other: &Self) -> bool {
        crate::utilities::ct_eq_hash_bytes((*self.inner).as_ref(), (*other.inner).as_ref())
    }
    // ct_eq_auto uses default impl
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

// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Fill with fresh random bytes of the specified length using the System RNG.
    ///
    /// Panics on RNG failure for fail-fast crypto code. Guarantees secure entropy
    /// from system sources.
    #[inline]
    pub fn from_random(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OsRng
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
        use serde::de::Visitor;
        struct DynamicVecVisitor;
        impl<'de> Visitor<'de> for DynamicVecVisitor {
            type Value = Dynamic<alloc::vec::Vec<u8>>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "a hex/base64url/bech32 string, a byte vector, or a sequence of bytes"
                )
            }

            #[cfg(any(
                feature = "encoding-hex",
                feature = "encoding-base64",
                feature = "encoding-bech32",
                feature = "encoding-bech32m"
            ))]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // Uses None for hints, maintaining historical decode priority for backward compatibility
                let bytes =
                    crate::utilities::decoding::try_decode_any(v, None).map_err(E::custom)?;
                Ok(Dynamic::new(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = alloc::vec::Vec::new();
                while let Some(value) = seq.next_element()? {
                    vec.push(value);
                }
                Ok(Dynamic::new(vec))
            }
        }
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(DynamicVecVisitor)
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
