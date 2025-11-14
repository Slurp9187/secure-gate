//! # `secure-types` — Inspired by `secrecy`: Zero-overhead, feature-gated secrets
//!
//! A thin, `no_std`-friendly wrapper for sensitive data (keys, passwords, etc.).
//! - Explicit access via `ExposeSecret` trait.
//! - Auto-zeroization on drop (via `zeroize`).
//! - Redacted in `Debug`.
//! - Fallback to plain `T` when `zeroize` disabled.
//! - Ergonomic: `secure!()` macro + type aliases.
//!
//! ## Features
//! - `zeroize` (default): Enables `SecretBox<T>` + wiping.
//! - `serde`: Deserialize support; Serialize opt-in via `SerializableSecret`.
//!
//! ## Usage
//! ```rust
//! use secure_types::{secure, SecureKey32, SecurePassword};
//! let key = secure!([u8; 32], rand::random());
//! let pw = secure!(String, "hunter2".into());
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

#[cfg(feature = "zeroize")]
pub use secrecy::{CloneableSecret, ExposeSecret, ExposeSecretMut, SecretBox, SerializableSecret};

#[cfg(feature = "zeroize")]
pub use secrecy::zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Serialize, Serializer};

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    convert::Infallible,
    fmt::{self, Debug},
    str::FromStr,
};

#[cfg(feature = "zeroize")]
type Inner<T: ?Sized> = SecretBox<T>;

#[cfg(not(feature = "zeroize"))]
type Inner<T: ?Sized> = Box<T>;

/// Core secure wrapper: `SecretBox<T>` (gated) or plain `T`.
pub struct Secure<T: ?Sized> {
    inner: Inner<T>,
}

impl<T: Sized> Secure<T> {
    /// Create from value.
    #[cfg(feature = "zeroize")]
    #[inline]
    pub fn new(value: T) -> Self
    where
        T: Zeroize,
    {
        Self {
            inner: SecretBox::new(Box::new(value)),
        }
    }

    #[cfg(not(feature = "zeroize"))]
    #[inline]
    pub fn new(value: T) -> Self {
        Self {
            inner: Box::new(value),
        }
    }

    /// Expose immutable reference.
    #[inline]
    pub fn expose(&self) -> &T {
        #[cfg(feature = "zeroize")]
        {
            self.inner.expose_secret()
        }
        #[cfg(not(feature = "zeroize"))]
        {
            &self.inner
        }
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized> Zeroize for Secure<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized> ZeroizeOnDrop for Secure<T> {}

#[cfg(feature = "zeroize")]
impl<T: CloneableSecret + Sized> Clone for Secure<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: Clone + Sized> Clone for Secure<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: ?Sized> Debug for Secure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<{}>([REDACTED])", core::any::type_name::<T>())
    }
}

impl<T: ?Sized> ExposeSecret<T> for Secure<T> {
    fn expose_secret(&self) -> &T {
        self.expose()
    }
}

impl<T: ?Sized> ExposeSecretMut<T> for Secure<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        #[cfg(feature = "zeroize")]
        {
            self.inner.expose_secret_mut()
        }
        #[cfg(not(feature = "zeroize"))]
        {
            &mut self.inner
        }
    }
}

#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> Secure<T> {
    /// Default instance.
    #[inline]
    pub fn default() -> Self {
        Self::new(T::default())
    }

    /// Init in-place with mut closure.
    pub fn init_with_mut(ctr: impl FnOnce(&mut T)) -> Self {
        Self {
            inner: SecretBox::init_with_mut(ctr),
        }
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: Default + Sized> Secure<T> {
    /// Default instance.
    #[inline]
    pub fn default() -> Self {
        Self::new(T::default())
    }

    /// Init in-place with mut closure.
    pub fn init_with_mut(ctr: impl FnOnce(&mut T)) -> Self {
        let mut value = T::default();
        ctr(&mut value);
        Self::new(value)
    }
}

#[cfg(feature = "zeroize")]
impl<T: CloneableSecret + Sized> Secure<T> {
    /// Init with closure (clone + zeroize local).
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self {
            inner: SecretBox::init_with(ctr),
        }
    }

    /// Fallible init with closure.
    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        SecretBox::try_init_with(ctr).map(|inner| Self { inner })
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: Sized> Secure<T> {
    /// Init with closure (clone + zeroize local).
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self::new(ctr())
    }

    /// Fallible init with closure.
    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        ctr().map(Self::new)
    }
}

#[cfg(all(feature = "serde", feature = "zeroize"))]
impl<'de, T> de::Deserialize<'de> for Secure<T>
where
    T: de::DeserializeOwned + CloneableSecret + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Self::try_init_with(|| T::deserialize(deserializer))
    }
}

#[cfg(all(feature = "serde", not(feature = "zeroize")))]
impl<'de, T> de::Deserialize<'de> for Secure<T>
where
    T: de::DeserializeOwned + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(all(feature = "serde", feature = "zeroize"))]
impl<T> Serialize for Secure<T>
where
    T: SerializableSecret + Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.expose().serialize(serializer)
    }
}

#[cfg(all(feature = "serde", not(feature = "zeroize")))]
impl<T> Serialize for Secure<T>
where
    T: Serialize + Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.expose().serialize(serializer)
    }
}

#[cfg(all(feature = "serde", feature = "zeroize"))]
impl<'de> de::Deserialize<'de> for Secure<str> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Into::into)
    }
}

#[cfg(all(feature = "serde", not(feature = "zeroize")))]
impl<'de> de::Deserialize<'de> for Secure<str> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|s| Self::new(s.into_boxed_str()))
    }
}

/// Secure byte slice: `Secure<[u8]>` (From<Vec<u8>>).
pub type SecureBytes = Secure<[u8]>;

impl From<Vec<u8>> for SecureBytes {
    fn from(vec: Vec<u8>) -> Self {
        let boxed = vec.into_boxed_slice();
        #[cfg(feature = "zeroize")]
        {
            Self {
                inner: SecretBox::new(boxed),
            }
        }
        #[cfg(not(feature = "zeroize"))]
        {
            Self { inner: boxed }
        }
    }
}

#[cfg(feature = "zeroize")]
impl Default for SecureBytes {
    fn default() -> Self {
        Vec::new().into()
    }
}

impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_vec())
    }
}

/// Secure string: `Secure<str>` (From<String>, From<&str>, FromStr).
pub type SecureStr = Secure<str>;

impl From<String> for SecureStr {
    fn from(s: String) -> Self {
        let boxed = s.into_boxed_str();
        #[cfg(feature = "zeroize")]
        {
            Self {
                inner: SecretBox::new(boxed),
            }
        }
        #[cfg(not(feature = "zeroize"))]
        {
            Self { inner: boxed }
        }
    }
}

impl From<&str> for SecureStr {
    fn from(s: &str) -> Self {
        Self::from(String::from(s))
    }
}

impl FromStr for SecureStr {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

#[cfg(feature = "zeroize")]
impl Default for SecureStr {
    fn default() -> Self {
        String::default().into()
    }
}

impl Clone for SecureStr {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_string())
    }
}

/// Convenience: Secure password alias.
pub type SecurePassword = Secure<String>;

impl From<&str> for SecurePassword {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

impl From<String> for SecurePassword {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

// Fixed-size aliases
pub type SecureKey32 = Secure<[u8; 32]>;
pub type SecureKey64 = Secure<[u8; 64]>;
pub type SecureIv = Secure<[u8; 16]>;
pub type SecureSalt = Secure<[u8; 16]>;
pub type SecureNonce12 = Secure<[u8; 12]>;
pub type SecureNonce16 = Secure<[u8; 16]>;
pub type SecureNonce24 = Secure<[u8; 24]>;

/// Ergonomic constructor macro.
#[macro_export]
macro_rules! secure {
    ($ty:ty, $expr:expr) => {
        $crate::Secure::<$ty>::new($expr)
    };
    ($ty:ty, [$($val:expr),+ $(,)?]) => {
        $crate::Secure::<$ty>::new([$($val),+])
    };
}

/// From array sugar.
macro_rules! impl_from_array {
    ($($N:literal),*) => {$(
        impl From<[u8; $N]> for $crate::Secure<[u8; $N]> {
            fn from(arr: [u8; $N]) -> Self {
                Self::new(arr)
            }
        }
    )*}
}
impl_from_array!(12, 16, 24, 32, 64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_password() {
        let pw = secure!(String, "test".into());
        assert_eq!(pw.expose(), "test");
    }

    #[test]
    #[cfg(feature = "zeroize")]
    fn test_init_with() {
        let key = Secure::<[u8; 32]>::init_with(|| [0xAA; 32]);
        assert_eq!(key.expose(), &[0xAA; 32][..]);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_deserialize() {
        let json = r#""secret""#;
        let pw: SecurePassword = serde_json::from_str(json).unwrap();
        assert_eq!(pw.expose(), "secret");
    }

    #[test]
    #[cfg(all(feature = "serde", feature = "zeroize"))]
    fn test_deserialize_str() {
        let json = r#""secret-str""#;
        let s: SecureStr = serde_json::from_str(json).unwrap();
        assert_eq!(s.expose(), "secret-str");
    }

    #[test]
    fn test_secure_str_from_str() {
        let s = SecureStr::from_str("test").unwrap();
        assert_eq!(s.expose(), "test");
    }
}
