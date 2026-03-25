//! secrecy **v0.10.1** compatibility layer.
//!
//! This module is a near-exact API mirror of [`secrecy`](https://crates.io/crates/secrecy)
//! v0.10.1 (`edition = "2021"`, `rust-version = "1.60"`).
//!
//! # Drop-in replacement
//!
//! The only required change for secrecy 0.10.x users is a mechanical import swap:
//!
//! ```text
//! // Before
//! use secrecy::{SecretBox, SecretString, SecretSlice, ExposeSecret, ExposeSecretMut};
//!
//! // After (one global find/replace)
//! use secure_gate::compat::v10::{SecretBox, SecretString, SecretSlice};
//! use secure_gate::compat::{ExposeSecret, ExposeSecretMut};
//! ```
//!
//! # Migration table
//!
//! | secrecy 0.10 | secure-gate native |
//! |---|---|
//! | `SecretBox<T>` | [`Dynamic<T>`](crate::Dynamic) |
//! | `SecretString` | `Dynamic<String>` |
//! | `SecretSlice<T>` | `Dynamic<Vec<T>>` |
//! | `ExposeSecret<T>` | [`RevealSecret`](crate::RevealSecret) |
//! | `ExposeSecretMut<T>` | [`RevealSecretMut`](crate::RevealSecretMut) |
//! | `CloneableSecret` | [`CloneableSecret`](crate::CloneableSecret) (with `cloneable` feature) |
//! | `SerializableSecret` | [`SerializableSecret`](crate::SerializableSecret) (with `serde-serialize` feature) |
//!
//! # Step-by-step migration
//!
//! 1. Replace `secrecy` dependency with `secure-gate` + `features = ["secrecy-compat"]`
//! 2. Find/replace `use secrecy::` → `use secure_gate::compat::v10::` (or `compat::` for traits)
//! 3. Gradually replace `v10::SecretBox<T>` with [`Dynamic<T>`](crate::Dynamic) using the
//!    provided [`From`] conversions
//! 4. Replace `compat::ExposeSecret` with [`RevealSecret`](crate::RevealSecret) — bridge impls
//!    on `Dynamic` and `Fixed` mean that call-sites using `.expose_secret()` continue to compile
//! 5. Remove `secrecy-compat` feature once fully migrated

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::str::FromStr;
use core::{any, fmt};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CloneableSecret, ExposeSecret, ExposeSecretMut};
#[cfg(feature = "serde-serialize")]
use super::SerializableSecret;

// ── SecretBox ────────────────────────────────────────────────────────────────

/// Heap-allocated secret wrapper — mirrors `secrecy::SecretBox`.
///
/// Stores the secret in a `Box<S>`, zeroizes on drop, and only exposes the inner
/// value through [`ExposeSecret`](super::ExposeSecret) /
/// [`ExposeSecretMut`](super::ExposeSecretMut). `Debug` always prints `[REDACTED]`.
///
/// # Migration to native secure-gate
///
/// For sized types, convert to [`Dynamic<S>`](crate::Dynamic) using the provided
/// `From` impl:
///
/// ```rust
/// # #[cfg(feature = "secrecy-compat")] {
/// use secure_gate::compat::v10::SecretBox;
/// use secure_gate::Dynamic;
///
/// let compat: SecretBox<String> = SecretBox::init_with(|| String::from("hunter2"));
/// let native: Dynamic<String> = compat.into();
/// # }
/// ```
pub struct SecretBox<S: Zeroize + ?Sized> {
    inner_secret: Box<S>,
}

impl<S: Zeroize + ?Sized> Zeroize for SecretBox<S> {
    fn zeroize(&mut self) {
        self.inner_secret.as_mut().zeroize();
    }
}

impl<S: Zeroize + ?Sized> Drop for SecretBox<S> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<S: Zeroize + ?Sized> ZeroizeOnDrop for SecretBox<S> {}

impl<S: Zeroize + ?Sized> From<Box<S>> for SecretBox<S> {
    fn from(source: Box<S>) -> Self {
        Self::new(source)
    }
}

impl<S: Zeroize + ?Sized> SecretBox<S> {
    /// Creates a `SecretBox` from a pre-boxed value.
    pub fn new(boxed_secret: Box<S>) -> Self {
        Self {
            inner_secret: boxed_secret,
        }
    }
}

impl<S: Zeroize + Default> SecretBox<S> {
    /// Creates a `SecretBox` by initializing the default value in-place via a mutable closure.
    pub fn init_with_mut(ctr: impl FnOnce(&mut S)) -> Self {
        let mut secret = Self::default();
        ctr(secret.inner_secret.as_mut());
        secret
    }
}

impl<S: Zeroize + Clone> SecretBox<S> {
    /// Creates a `SecretBox` from the return value of `ctr`.
    ///
    /// Makes an effort to zeroize the stack copy before boxing, but this is
    /// best-effort. Prefer [`init_with_mut`](Self::init_with_mut) when possible.
    pub fn init_with(ctr: impl FnOnce() -> S) -> Self {
        let mut data = ctr();
        let secret = Self {
            inner_secret: Box::new(data.clone()),
        };
        data.zeroize();
        secret
    }

    /// Fallible variant of [`init_with`](Self::init_with).
    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<S, E>) -> Result<Self, E> {
        let mut data = ctr()?;
        let secret = Self {
            inner_secret: Box::new(data.clone()),
        };
        data.zeroize();
        Ok(secret)
    }
}

impl<S: Zeroize + Default> Default for SecretBox<S> {
    fn default() -> Self {
        Self {
            inner_secret: Box::<S>::default(),
        }
    }
}

impl<S: Zeroize + ?Sized> fmt::Debug for SecretBox<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBox<{}>([REDACTED])", any::type_name::<S>())
    }
}

impl<S: CloneableSecret> Clone for SecretBox<S> {
    fn clone(&self) -> Self {
        SecretBox {
            inner_secret: self.inner_secret.clone(),
        }
    }
}

impl<S: Zeroize + ?Sized> ExposeSecret<S> for SecretBox<S> {
    fn expose_secret(&self) -> &S {
        self.inner_secret.as_ref()
    }
}

impl<S: Zeroize + ?Sized> ExposeSecretMut<S> for SecretBox<S> {
    fn expose_secret_mut(&mut self) -> &mut S {
        self.inner_secret.as_mut()
    }
}

// ── SecretString ─────────────────────────────────────────────────────────────

/// Secret string type — mirrors `secrecy::SecretString`.
///
/// Type alias for `SecretBox<str>`. Construct from [`String`] or `&str`.
/// Prefer [`Dynamic<String>`](crate::Dynamic) for new code.
pub type SecretString = SecretBox<str>;

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::from(s.into_boxed_str())
    }
}

impl<'a> From<&'a str> for SecretString {
    fn from(s: &'a str) -> Self {
        Self::from(String::from(s))
    }
}

impl FromStr for SecretString {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        SecretBox {
            inner_secret: self.inner_secret.clone(),
        }
    }
}

impl Default for SecretString {
    fn default() -> Self {
        String::default().into()
    }
}

// ── SecretSlice ───────────────────────────────────────────────────────────────

/// Secret slice type — mirrors `secrecy::SecretSlice`.
///
/// Type alias for `SecretBox<[S]>`. Construct from [`Vec<S>`].
/// Prefer [`Dynamic<Vec<S>>`](crate::Dynamic) for new code.
pub type SecretSlice<S> = SecretBox<[S]>;

impl<S> From<Vec<S>> for SecretSlice<S>
where
    S: Zeroize,
    [S]: Zeroize,
{
    fn from(vec: Vec<S>) -> Self {
        Self::from(vec.into_boxed_slice())
    }
}

impl<S> Clone for SecretSlice<S>
where
    S: CloneableSecret + Zeroize,
    [S]: Zeroize,
{
    fn clone(&self) -> Self {
        SecretBox {
            inner_secret: Vec::from(&*self.inner_secret).into_boxed_slice(),
        }
    }
}

impl<S> Default for SecretSlice<S>
where
    S: Zeroize,
    [S]: Zeroize,
{
    fn default() -> Self {
        Vec::<S>::new().into()
    }
}

// ── Conversions: SecretBox ↔ Dynamic ─────────────────────────────────────────

/// Converts a `SecretBox<S>` into a [`Dynamic<S>`](crate::Dynamic) (primary migration path).
///
/// Requires `S: Clone` because the inner `Box<S>` cannot be moved out of `SecretBox`
/// without unsafe code (`SecretBox` has a `Drop` impl). The clone is immediately
/// wrapped in `Dynamic` and the original is zeroized on drop.
///
/// For zero-copy migration, construct `Dynamic<S>` directly instead.
impl<S: Clone + Zeroize + 'static> From<SecretBox<S>> for crate::Dynamic<S> {
    fn from(sb: SecretBox<S>) -> Self {
        crate::Dynamic::new(sb.inner_secret.as_ref().clone())
    }
}

/// Converts a [`Dynamic<String>`](crate::Dynamic) back into a `SecretBox<String>`.
///
/// Clones the inner `String`. Both the source and the new wrapper are zeroized on drop.
impl From<crate::Dynamic<String>> for SecretBox<String> {
    fn from(d: crate::Dynamic<String>) -> Self {
        let val = <crate::Dynamic<String> as crate::RevealSecret>::expose_secret(&d).clone();
        SecretBox::new(Box::new(val))
    }
}

/// Converts a [`Dynamic<String>`](crate::Dynamic) into a `SecretString` (= `SecretBox<str>`).
///
/// Clones the inner string. Both ends are zeroized on drop.
impl From<crate::Dynamic<String>> for SecretString {
    fn from(d: crate::Dynamic<String>) -> Self {
        let val = <crate::Dynamic<String> as crate::RevealSecret>::expose_secret(&d).clone();
        SecretString::from(val)
    }
}

/// Converts a [`Dynamic<Vec<S>>`](crate::Dynamic) back into a `SecretBox<Vec<S>>`.
///
/// Clones the inner `Vec`. Both ends are zeroized on drop.
impl<S: Clone + Zeroize + 'static> From<crate::Dynamic<Vec<S>>> for SecretBox<Vec<S>> {
    fn from(d: crate::Dynamic<Vec<S>>) -> Self {
        let val = <crate::Dynamic<Vec<S>> as crate::RevealSecret>::expose_secret(&d).clone();
        SecretBox::new(Box::new(val))
    }
}

/// Converts a `SecretString` (= `SecretBox<str>`) into a [`Dynamic<String>`](crate::Dynamic).
///
/// Clones the inner `str` into a new `String`. Both ends are zeroized on drop.
impl From<SecretString> for crate::Dynamic<String> {
    fn from(sb: SecretString) -> Self {
        let val = String::from(sb.inner_secret.as_ref());
        crate::Dynamic::new(val)
    }
}

// ── Serde ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "serde-deserialize")]
impl<'de, T> serde::Deserialize<'de> for SecretBox<T>
where
    T: Zeroize + Clone + serde::de::DeserializeOwned + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_init_with(|| T::deserialize(deserializer))
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Into::into)
    }
}

#[cfg(feature = "serde-serialize")]
impl<T> serde::Serialize for SecretBox<T>
where
    T: Zeroize + SerializableSecret + serde::Serialize + Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner_secret.as_ref().serialize(serializer)
    }
}

// ── Legacy alias ─────────────────────────────────────────────────────────────

/// Legacy type alias for [`SecretBox`] — mirrors `secrecy::Secret` from secrecy <0.9.
///
/// secrecy 0.9 renamed `Secret<T>` to `SecretBox<T>`. Use [`SecretBox`] instead.
///
/// **Note:** secrecy 0.8 users should use [`v08::Secret`](super::v08::Secret) instead,
/// which mirrors the original stack-allocated semantics.
#[deprecated(since = "0.8.0", note = "Use `SecretBox` instead (mirrors secrecy >=0.9)")]
pub type Secret<S> = SecretBox<S>;
