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

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

#[cfg(feature = "zeroize")]
use secrecy::{CloneableSecret, SecretBox};

#[cfg(all(feature = "serde", feature = "zeroize"))]
use secrecy::SerializableSecret;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{de, Serialize, Serializer};

#[cfg(feature = "zeroize")]
pub use secrecy::{ExposeSecret, ExposeSecretMut};

#[cfg(not(feature = "zeroize"))]
pub trait ExposeSecret<T: ?Sized> {
    /// Expose the secret: auditable access point.
    fn expose_secret(&self) -> &T;
}

#[cfg(not(feature = "zeroize"))]
pub trait ExposeSecretMut<T: ?Sized> {
    /// Expose mutable secret.
    fn expose_secret_mut(&mut self) -> &mut T;
}

use alloc::string::ToString;
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    any,
    convert::Infallible,
    fmt::{self, Debug},
    str::FromStr,
};

/// Core secure wrapper: `SecretBox<T>` (gated) or `Box<T>`.
#[cfg(feature = "zeroize")]
pub struct Secure<T: Zeroize + ?Sized>(SecretBox<T>);

#[cfg(not(feature = "zeroize"))]
pub struct Secure<T: ?Sized>(Box<T>);

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> Secure<T> {
    /// Create from value.
    #[inline]
    pub fn new(value: T) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: Sized> Secure<T> {
    /// Create from value.
    #[inline]
    pub fn new(value: T) -> Self {
        Self(Box::new(value))
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> Secure<T> {
    /// Expose immutable reference.
    #[inline]
    pub fn expose(&self) -> &T {
        self.0.expose_secret()
    }

    /// Expose mutable reference.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        self.0.expose_secret_mut()
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> Secure<T> {
    /// Expose immutable reference.
    #[inline]
    pub fn expose(&self) -> &T {
        &*self.0
    }

    /// Expose mutable reference.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut *self.0
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> Debug for Secure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<{}>([REDACTED])", any::type_name::<T>())
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> Debug for Secure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<{}>([REDACTED])", any::type_name::<T>())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ExposeSecret<T> for Secure<T> {
    fn expose_secret(&self) -> &T {
        self.0.expose_secret()
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ExposeSecretMut<T> for Secure<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        self.0.expose_secret_mut()
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> ExposeSecret<T> for Secure<T> {
    fn expose_secret(&self) -> &T {
        self.expose()
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> ExposeSecretMut<T> for Secure<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        self.expose_mut()
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Clone for Secure<T> {
    fn clone(&self) -> Self {
        Self::new(self.expose().clone())
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: Clone + ?Sized> Clone for Secure<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> Default for Secure<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: Default + Sized> Default for Secure<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> Zeroize for Secure<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ZeroizeOnDrop for Secure<T> {}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Secure<T> {
    /// Init with closure (clone + zeroize local).
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self(SecretBox::init_with(ctr))
    }

    /// Fallible init with closure.
    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        SecretBox::try_init_with(ctr).map(Self)
    }

    /// Consume and return a boxed inner value.
    pub fn into_inner(self) -> Box<T> {
        Box::new(self.expose().clone())
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

#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> Secure<T> {
    /// Init in-place with mut closure.
    pub fn init_with_mut(ctr: impl FnOnce(&mut T)) -> Self {
        Self(SecretBox::init_with_mut(ctr))
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> Secure<T> {
    /// Consume and return the inner boxed value.
    pub fn into_inner(self) -> Box<T> {
        self.0
    }
}

#[cfg(all(feature = "serde", feature = "zeroize"))]
impl<'de, T> de::Deserialize<'de> for Secure<T>
where
    T: de::Deserialize<'de> + Zeroize + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let value = T::deserialize(deserializer)?;
        Ok(Self::new(value))
    }
}

#[cfg(all(feature = "serde", not(feature = "zeroize")))]
impl<'de, T> de::Deserialize<'de> for Secure<T>
where
    T: de::Deserialize<'de> + Sized,
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
    T: SerializableSecret + Serialize + Sized + Zeroize,
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

/// Secure byte slice: `Secure<[u8]>` (From<Vec<u8>>).
pub type SecureBytes = Secure<[u8]>;

impl From<Vec<u8>> for SecureBytes {
    fn from(vec: Vec<u8>) -> Self {
        let boxed = vec.into_boxed_slice();
        #[cfg(feature = "zeroize")]
        {
            Self(SecretBox::new(boxed))
        }
        #[cfg(not(feature = "zeroize"))]
        {
            Self(boxed)
        }
    }
}

#[cfg(feature = "zeroize")]
impl Clone for SecureBytes
where
    [u8]: Zeroize,
{
    fn clone(&self) -> Self {
        Self::from(self.expose().to_vec())
    }
}

#[cfg(not(feature = "zeroize"))]
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
            Self(SecretBox::new(boxed))
        }
        #[cfg(not(feature = "zeroize"))]
        {
            Self(boxed)
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
impl Clone for SecureStr {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_string())
    }
}

#[cfg(not(feature = "zeroize"))]
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

/// Secure 32-byte key (e.g., for AES-256).
pub type SecureKey32 = Secure<[u8; 32]>;
/// Secure 64-byte key (e.g., for longer hashes).
pub type SecureKey64 = Secure<[u8; 64]>;
/// Secure IV (16 bytes, e.g., for AES-GCM).
pub type SecureIv = Secure<[u8; 16]>;
/// Secure salt (16 bytes).
pub type SecureSalt = Secure<[u8; 16]>;
/// Secure 12-byte nonce (e.g., for ChaCha20-Poly1305).
pub type SecureNonce12 = Secure<[u8; 12]>;
/// Secure 16-byte nonce (e.g., for AES-GCM).
pub type SecureNonce16 = Secure<[u8; 16]>;
/// Secure 24-byte nonce.
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
        impl From<[u8; $N]> for Secure<[u8; $N]> {
            fn from(arr: [u8; $N]) -> Self { Self::new(arr) }
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
        let val = Secure::<u32>::init_with(|| 42u32);
        assert_eq!(*val.expose(), 42);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_deserialize() {
        let json = r#""secret""#;
        let pw: SecurePassword = serde_json::from_str(json).unwrap();
        assert_eq!(pw.expose(), "secret");
    }
}
