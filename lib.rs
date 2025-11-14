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
//! let pw  = secure!(String, "hunter2".into());
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

#[cfg(feature = "zeroize")]
use secrecy::SecretBox;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Serialize, Serializer};

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    convert::Infallible,
    fmt::{self, Debug},
    str::FromStr,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Marker trait for secrets that can be cloned (opt-in for safety).
#[cfg(feature = "zeroize")]
pub trait CloneableSecret: Clone + Zeroize {}

#[cfg(feature = "zeroize")]
impl CloneableSecret for u8 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for u16 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for u32 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for u64 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for u128 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for usize {}
#[cfg(feature = "zeroize")]
impl<T: CloneableSecret, const N: usize> CloneableSecret for [T; N] {}

/// Expose a reference to the inner secret (explicit access only).
pub trait ExposeSecret<S: ?Sized> {
    /// Expose the secret: auditable access point.
    fn expose_secret(&self) -> &S;
}

/// Expose a mutable reference to the inner secret.
pub trait ExposeSecretMut<S: ?Sized> {
    /// Expose mutable secret.
    fn expose_secret_mut(&mut self) -> &mut S;
}

/// Marker for types safe to serialize via `serde` (opt-in to prevent leaks).
#[cfg(feature = "serde")]
pub trait SerializableSecret: Serialize {}

/// Core secure wrapper: `SecretBox<T>` (gated) or plain `T`.
#[derive(Debug)]
pub struct Secure<T: ?Sized>(Inner<T>);

#[cfg(feature = "zeroize")]
type Inner<T: ?Sized> = SecretBox<T>;

#[cfg(not(feature = "zeroize"))]
type Inner<T: ?Sized> = T;

/* ---------- Constructors (require Sized) ---------- */
impl<T: Sized> Secure<T> {
    /// Create from value.
    #[inline]
    pub fn new(inner: T) -> Self {
        #[cfg(feature = "zeroize")]
        {
            Self(SecretBox::new(Box::new(inner)))
        }
        #[cfg(not(feature = "zeroize"))]
        {
            Self(inner)
        }
    }

    /// Consume and return inner (zeroizes if gated).
    #[inline]
    pub fn into_inner(self) -> T {
        #[cfg(feature = "zeroize")]
        {
            *self.0.into_inner()
        }
        #[cfg(not(feature = "zeroize"))]
        {
            self.0
        }
    }
}

/* ---------- Immutable expose (works for ?Sized) ---------- */
impl<T: ?Sized> Secure<T> {
    /// Expose immutable reference.
    #[inline]
    pub fn expose(&self) -> &T {
        #[cfg(feature = "zeroize")]
        {
            self.0.expose_secret()
        }
        #[cfg(not(feature = "zeroize"))]
        {
            &self.0
        }
    }
}

/* ---------- Zeroize delegation ---------- */
#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> Zeroize for Secure<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ZeroizeOnDrop for Secure<T> {}

/* ---------- Clone delegation ---------- */
#[cfg(feature = "zeroize")]
impl<T: CloneableSecret + Sized> Clone for Secure<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/* ---------- ExposeSecret trait impls ---------- */
#[cfg(feature = "zeroize")]
impl<T: ?Sized> ExposeSecret<T> for Secure<T> {
    fn expose_secret(&self) -> &T {
        self.expose()
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized> ExposeSecretMut<T> for Secure<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        self.0.expose_secret_mut()
    }
}

/* ---------- Plain-mode trait impls ---------- */
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> ExposeSecret<T> for Secure<T> {
    fn expose_secret(&self) -> &T {
        &self.0
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> ExposeSecretMut<T> for Secure<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/* ---------- init helpers (gated) ---------- */
#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> Secure<T> {
    pub fn default() -> Self {
        Self::new(T::default())
    }

    pub fn init_with_mut(ctr: impl FnOnce(&mut T)) -> Self {
        let mut inner = T::default();
        ctr(&mut inner);
        Self::new(inner)
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Secure<T> {
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        let mut data = ctr();
        let secret = Self::new(data.clone());
        data.zeroize();
        secret
    }

    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        let mut data = ctr()?;
        let secret = Self::new(data.clone());
        data.zeroize();
        Ok(secret)
    }
}

/* ---------- serde (gated) ---------- */
#[cfg(feature = "serde")]
impl<'de, T> de::Deserialize<'de> for Secure<T>
where
    T: de::DeserializeOwned + Zeroize + Clone + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Self::try_init_with(|| T::deserialize(deserializer))
    }
}

#[cfg(feature = "serde")]
impl<T> Serialize for Secure<T>
where
    T: SerializableSecret + Serialize + Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.expose().serialize(serializer)
    }
}

/* ---------- Secure byte slice ---------- */
pub type SecureBytes = Secure<[u8]>;

impl From<Vec<u8>> for SecureBytes {
    fn from(vec: Vec<u8>) -> Self {
        #[cfg(feature = "zeroize")]
        {
            Self::new(vec.into_boxed_slice())
        }
        #[cfg(not(feature = "zeroize"))]
        {
            Self(vec.into_boxed_slice())
        }
    }
}

#[cfg(feature = "zeroize")]
impl Clone for SecureBytes
where
    [u8]: Zeroize,
{
    fn clone(&self) -> Self {
        Self(Vec::from(self.expose()).into_boxed_slice())
    }
}

/* ---------- Secure string slice ---------- */
pub type SecureStr = Secure<str>;

impl From<String> for SecureStr {
    fn from(s: String) -> Self {
        #[cfg(feature = "zeroize")]
        {
            Self::new(s.into_boxed_str())
        }
        #[cfg(not(feature = "zeroize"))]
        {
            Self(s.into_boxed_str())
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
        Self(self.expose().to_string().into())
    }
}

/* ---------- Secure password (owned) ---------- */
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

/* ---------- Fixed-size aliases ---------- */
pub type SecureKey32 = Secure<[u8; 32]>;
pub type SecureKey64 = Secure<[u8; 64]>;
pub type SecureIv = Secure<[u8; 16]>;
pub type SecureSalt = Secure<[u8; 16]>;
pub type SecureNonce12 = Secure<[u8; 12]>;
pub type SecureNonce16 = Secure<[u8; 16]>;
pub type SecureNonce24 = Secure<[u8; 24]>;

/* ---------- `secure!` macro ---------- */
#[macro_export]
macro_rules! secure {
    ($ty:ty, $expr:expr) => {
        $crate::Secure::<$ty>::new($expr)
    };
    ($ty:ty, [$($val:expr),+ $(,)?]) => {
        $crate::Secure::<$ty>::new([$($val),+])
    };
}

/* ---------- From<[u8; N]> sugar ---------- */
macro_rules! impl_from_array {
    ($($N:literal),*) => {$(
        impl From<[u8; $N]> for Secure<[u8; $N]> {
            fn from(arr: [u8; $N]) -> Self {
                Self::new(arr)
            }
        }
    )*}
}
impl_from_array!(12, 16, 24, 32, 64);

/* ---------- Tests ---------- */
#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    #[test]
    fn password_roundtrip() {
        let pw: SecurePassword = "hunter2".into();
        assert_eq!(pw.expose(), "hunter2");
    }

    #[test]
    fn key_from_array() {
        let key: SecureKey32 = [0xAA; 32].into();
        assert_eq!(key.expose(), &[0xAA; 32]);
    }

    #[test]
    #[cfg(feature = "zeroize")]
    fn mut_access() {
        let mut key: SecureKey32 = [0u8; 32].into();
        let key_mut = key.expose_secret_mut();
        key_mut[0] = 0xFF;
        assert_eq!(key_mut[0], 0xFF);
    }

    #[test]
    #[cfg(feature = "zeroize")]
    fn init_with() {
        let key = Secure::<[u8; 32]>::init_with(|| [0xAA; 32]);
        assert_eq!(key.expose(), &[0xAA; 32]);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_roundtrip() {
        let json = r#""secret""#;
        let pw: SecurePassword = serde_json::from_str(json).unwrap();
        assert_eq!(pw.expose(), "secret");
    }
}
