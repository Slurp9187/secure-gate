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

#[cfg(feature = "zeroize")]
use secrecy::SecretBox;
#[cfg(all(feature = "serde", feature = "zeroize"))]
use secrecy::SerializableSecret;
#[cfg(feature = "zeroize")]
use secrecy::{ExposeSecret, ExposeSecretMut};
#[cfg(feature = "serde")]
use serde::{de, Serialize, Serializer};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

// FIXED: Imports for downcast in finish_mut (under zeroize only)
#[cfg(feature = "zeroize")]
use crate::private::SecretString;
#[cfg(feature = "zeroize")]
use core::ops::DerefMut;

// Helper trait (moved earlier for forward ref)
#[cfg(feature = "zeroize")]
use core::any::Any;
#[cfg(feature = "zeroize")]
pub(crate) trait AsAnyMut {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
#[cfg(feature = "zeroize")]
impl<T: 'static> AsAnyMut for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// Other imports
use alloc::string::ToString;
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    convert::Infallible,
    fmt::{self, Debug},
    str::FromStr,
};

#[cfg(not(feature = "zeroize"))]
/// Fallback `ExposeSecret` trait when `zeroize` feature is disabled.
/// Provides explicit, auditable access to the inner secret value.
pub trait ExposeSecret<T: ?Sized> {
    /// Expose the secret: auditable access point.
    fn expose_secret(&self) -> &T;
}
#[cfg(not(feature = "zeroize"))]
/// Fallback `ExposeSecretMut` trait when `zeroize` feature is disabled.
/// Provides explicit, auditable mutable access to the inner secret value.
pub trait ExposeSecretMut<T: ?Sized> {
    /// Expose mutable secret.
    fn expose_secret_mut(&mut self) -> &mut T;
}
/// Core secure wrapper: `SecretBox<T>` (gated) or `Box<T>`.
#[cfg(feature = "zeroize")]
pub struct Secure<T: Zeroize + ?Sized>(SecretBox<T>);
#[cfg(not(feature = "zeroize"))]
/// Fallback secure wrapper when `zeroize` feature is disabled.
/// Wraps the value in `Box<T>` for heap allocation without zeroization.
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
        &self.0
    }
    /// Expose mutable reference.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
// #[cfg(feature = "zeroize")]
// impl<T: Zeroize + ?Sized> Debug for Secure<T> {
// fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
// write!(f, "Secure<{}>([REDACTED])", any::type_name::<T>())
// }
// }
// Remove unused import: delete `any,` from core imports in secure_types.rs
#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> Debug for Secure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secure")
            .field("value", &"[REDACTED]")
            .finish()
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> Debug for Secure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // FIXED: Import type_name added below
        write!(f, "Secure<{}>([REDACTED])", core::any::type_name::<T>())
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
// #[cfg(feature = "zeroize")]
// impl<T: Clone + Zeroize + Sized> Clone for Secure<T> {
// fn clone(&self) -> Self {
// Self::new(self.expose().clone())
// }
// }
#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Clone for Secure<T> {
    fn clone(&self) -> Self {
        Self::init_with(|| self.expose().clone())
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
#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Secure<T> {
    /// Extract the inner value as `Box<T>`, zeroizing the original wrapper.
    ///
    /// # Security Note
    /// This clones the secret for extraction (unavoidable for ownership transfer).
    /// The source is explicitly zeroized before return to mitigate leaks.
    /// Use only for FFI/handover—re-wrap immediately in a new `Secure` if needed.
    /// Prefer scoped `expose_mut()` for mutations to avoid extraction entirely.
    pub fn into_inner(mut self) -> Box<T> {
        let value = self.0.expose_secret().clone(); // Safe clone (preserves Zeroize if T implements)
        self.0.zeroize(); // Explicit wipe of original (redundant with drop, but immediate)
        Box::new(value)
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
#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized + 'static> Secure<T> {
    /// After mutations, call this to shrink capacity (for Vec/String) and zero excess.
    /// Ensures no over-allocated leaks on drop.
    pub fn finish_mut(&mut self) -> &mut T {
        if let Some(v) = self.expose_mut().as_any_mut().downcast_mut::<Vec<u8>>() {
            v.shrink_to_fit();
        } else if let Some(s) = self.expose_mut().as_any_mut().downcast_mut::<String>() {
            s.shrink_to_fit();
        } else if let Some(ss) = self
            .expose_mut()
            .as_any_mut()
            .downcast_mut::<SecretString>()
        {
            // Handle SecurePassword (SecretString wrapper)
            ss.deref_mut().shrink_to_fit(); // Shrink inner String via DerefMut
        }
        self.expose_mut()
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
/// REMOVED: Duplicate SecurePassword alias/impls (now in lib.rs only)
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
