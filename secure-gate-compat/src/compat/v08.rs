//! secrecy **v0.8.0** compatibility layer.
//!
//! This module is a near-exact API mirror of [`secrecy`](https://crates.io/crates/secrecy)
//! v0.8.0 (`edition = "2018"`, `rust-version = "~1.52"`).
//!
//! # Drop-in replacement
//!
//! The only required change for secrecy 0.8.x users is a mechanical import swap:
//!
//! ```text
//! // Before
//! use secrecy::{Secret, SecretString, SecretVec, DebugSecret, CloneableSecret, ExposeSecret};
//!
//! // After (one global find/replace)
//! use secure_gate::compat::v08::{Secret, SecretString, SecretVec, DebugSecret};
//! use secure_gate::compat::{CloneableSecret, ExposeSecret};
//! ```
//!
//! # API table
//!
//! | secrecy 0.8 | This module | Notes |
//! |---|---|---|
//! | `Secret<S>` | [`Secret<S>`] | Stack/inline; `S: Zeroize` |
//! | `SecretString` | [`SecretString`] | = `Secret<String>` |
//! | `SecretVec<T>` | [`SecretVec<T>`] | = `Secret<Vec<T>>` |
//! | `SecretBox<S>` | [`SecretBox<S>`] | = `Secret<Box<S>>` |
//! | `ExposeSecret<S>` | [`compat::ExposeSecret`](super::ExposeSecret) | Shared trait |
//! | `CloneableSecret` | [`compat::CloneableSecret`](super::CloneableSecret) | Shared trait |
//! | `DebugSecret` | [`DebugSecret`] | v0.8-only trait |
//! | `SerializableSecret` | [`compat::SerializableSecret`](super::SerializableSecret) | Shared trait |
//! | `Zeroize` re-export | [`compat::zeroize`](super::zeroize) | Shared re-export |
//!
//! # Key differences from v0.10
//!
//! - `Secret<S>` is **stack-allocated** (inline `S`) — no `Box`. Use `SecretBox<S>` for
//!   heap-allocated variants.
//! - No [`ExposeSecretMut`](super::ExposeSecretMut) — mutable access was added in v0.9.
//! - [`DebugSecret`] trait is required for `Debug` impls. Not present in v0.10.
//!
//! # Step-by-step migration
//!
//! 1. Replace `secrecy` dependency with `secure-gate` + `features = ["secrecy-compat"]`
//! 2. Find/replace `use secrecy::` → `use secure_gate::compat::v08::` (types) or
//!    `use secure_gate::compat::` (traits)
//! 3. Gradually replace `v08::Secret<String>` with [`Dynamic<String>`](crate::Dynamic) using
//!    the provided [`From`] conversions
//! 4. Replace `v08::Secret<[T; N]>` with [`Fixed<[T; N]>`](crate::Fixed)
//! 5. Remove `secrecy-compat` feature once fully migrated

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::str::FromStr;
use core::{any, fmt};
use zeroize::Zeroize;

use super::CloneableSecret;
use super::ExposeSecret;
#[cfg(feature = "serde-serialize")]
use super::SerializableSecret;

// ── DebugSecret ───────────────────────────────────────────────────────────────

/// Opt-in debug display for secret types — mirrors `secrecy::DebugSecret`.
///
/// Implementing this trait on a type `S` enables `Debug for Secret<S>`, which
/// will call `S::debug_secret` instead of exposing the value.
///
/// The default impl prints `[REDACTED typename]`. Override to customize the label.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "secrecy-compat")] {
/// extern crate secure_gate_compat;
/// use secure_gate_compat::compat::v08::{DebugSecret, Secret};
///
/// struct ApiKey(String);
/// impl zeroize::Zeroize for ApiKey { fn zeroize(&mut self) { self.0.zeroize(); } }
/// impl DebugSecret for ApiKey {}
///
/// let key = Secret::new(ApiKey(String::from("sk_live_xyz")));
/// // prints: Secret([REDACTED secrecy_compat_test::ApiKey]) or similar
/// println!("{:?}", key);
/// # }
/// ```
pub trait DebugSecret {
    /// Format type-identifying information about the secret (never the value itself).
    fn debug_secret(f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("[REDACTED ")?;
        f.write_str(any::type_name::<Self>())?;
        f.write_str("]")
    }
}

// Blanket impls mirroring v0.8 — upgraded from size-list macros to const generics.
impl<T: fmt::Debug, const N: usize> DebugSecret for [T; N] {}
impl DebugSecret for String {}
impl<S: DebugSecret + Zeroize> DebugSecret for Box<S> {}
impl<S: DebugSecret + Zeroize> DebugSecret for Vec<S> {}

// ── Additional CloneableSecret impls (v0.8-specific) ─────────────────────────
//
// secrecy 0.8 provides `CloneableSecret` for `String` and `Vec<S: CloneableSecret>`.
// These are not included in the shared mod.rs (where the trait is defined) because
// v0.10 deliberately does NOT make `SecretBox<String>` auto-cloneable.

impl CloneableSecret for String {}
impl<S: CloneableSecret + Zeroize> CloneableSecret for Vec<S> {}

// ── Secret<S> ────────────────────────────────────────────────────────────────

/// Stack/inline secret wrapper — mirrors `secrecy::Secret`.
///
/// Stores the secret value **directly** (no heap allocation). On drop, calls
/// `S::zeroize()` to wipe the memory. Access is only possible through
/// [`ExposeSecret`](super::ExposeSecret).
///
/// # Generic parameter
///
/// `S` must implement [`Zeroize`] for secure erasure on drop.
///
/// # Debug
///
/// `Debug` is only available when `S: DebugSecret`. The output is always
/// `Secret([REDACTED typename])` — the inner value is never printed.
///
/// # Migration to native secure-gate
///
/// ```rust
/// # #[cfg(feature = "secrecy-compat")] {
/// extern crate secure_gate_compat;
/// use secure_gate_compat::compat::v08::Secret;
/// use secure_gate_compat::Dynamic;
///
/// // String → heap-allocated Dynamic<String>
/// let old: Secret<String> = Secret::new(String::from("hunter2"));
/// let native: Dynamic<String> = old.into();
///
/// // [u8; 32] → stack-allocated Fixed<[u8; 32]>
/// use secure_gate_compat::Fixed;
/// let key: Secret<[u8; 32]> = Secret::new([0xABu8; 32]);
/// let fixed: Fixed<[u8; 32]> = key.into();
/// # }
/// ```
pub struct Secret<S>
where
    S: Zeroize,
{
    inner_secret: S,
}

impl<S: Zeroize> Secret<S> {
    /// Takes ownership of a secret value.
    pub fn new(secret: S) -> Self {
        Secret {
            inner_secret: secret,
        }
    }
}

impl<S: Zeroize> ExposeSecret<S> for Secret<S> {
    fn expose_secret(&self) -> &S {
        &self.inner_secret
    }
}

impl<S: Zeroize> From<S> for Secret<S> {
    fn from(secret: S) -> Self {
        Self::new(secret)
    }
}

impl<S: CloneableSecret> Clone for Secret<S> {
    fn clone(&self) -> Self {
        Secret {
            inner_secret: self.inner_secret.clone(),
        }
    }
}

impl<S: Zeroize + DebugSecret> fmt::Debug for Secret<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(")?;
        S::debug_secret(f)?;
        f.write_str(")")
    }
}

impl<S: Zeroize> Drop for Secret<S> {
    fn drop(&mut self) {
        self.inner_secret.zeroize();
    }
}

// ── SecretString ─────────────────────────────────────────────────────────────

/// Secret string type — mirrors `secrecy::SecretString` (v0.8).
///
/// Type alias for `Secret<String>`. Implements `FromStr`, `Clone` (via
/// `String: CloneableSecret`), and `Debug` (via `String: DebugSecret`).
///
/// Note: secrecy 0.10's `SecretString` is `SecretBox<str>` (different type).
/// Use [`v10::SecretString`](super::v10::SecretString) when migrating to v0.10 semantics.
pub type SecretString = Secret<String>;

impl FromStr for SecretString {
    type Err = core::convert::Infallible;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Ok(SecretString::new(src.to_string()))
    }
}

// ── SecretVec ─────────────────────────────────────────────────────────────────

/// Secret vector type — mirrors `secrecy::SecretVec` (v0.8).
///
/// Type alias for `Secret<Vec<T>>`.
pub type SecretVec<T> = Secret<Vec<T>>;

// ── SecretBox ─────────────────────────────────────────────────────────────────

/// Secret boxed type — mirrors `secrecy::SecretBox` (v0.8).
///
/// Type alias for `Secret<Box<S>>`. Note that this is **different** from
/// [`v10::SecretBox`](super::v10::SecretBox), which is a newtype around `Box<S>` with
/// `?Sized` support. This v0.8 variant stores `Box<S>` as the `S` in `Secret<S>`.
///
/// # Zeroize requirement
///
/// `Box<S>` must implement [`Zeroize`]. In zeroize ≥ 1.8, this is only provided for
/// `Box<[Z]>` (heap slices, `Z: Zeroize`) and `Box<str>`. For sized secret buffers,
/// prefer [`v10::SecretBox`](super::v10::SecretBox) or the native
/// [`Dynamic<T>`](crate::Dynamic).
pub type SecretBox<S> = Secret<Box<S>>;

// ── Serde ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "serde-deserialize")]
impl<'de, T> serde::Deserialize<'de> for Secret<T>
where
    T: Zeroize + Clone + serde::de::DeserializeOwned + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Secret::new)
    }
}

#[cfg(feature = "serde-serialize")]
impl<T> serde::Serialize for Secret<T>
where
    T: Zeroize + SerializableSecret + serde::Serialize + Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner_secret.serialize(serializer)
    }
}

// ── Conversions: Secret ↔ Dynamic / Fixed ────────────────────────────────────
//
// All conversions require Clone because `Secret<S>` has a `Drop` impl and
// `#![forbid(unsafe_code)]` prevents us from moving the field out directly.
// The clone is brief: the original is zeroized when it drops at the end of the
// conversion function body.

/// Converts `Secret<String>` into a [`Dynamic<String>`](crate::Dynamic).
impl From<Secret<String>> for crate::Dynamic<String> {
    fn from(s: Secret<String>) -> Self {
        crate::Dynamic::new(s.inner_secret.clone())
    }
}

/// Converts a [`Dynamic<String>`](crate::Dynamic) into `Secret<String>`.
impl From<crate::Dynamic<String>> for Secret<String> {
    fn from(d: crate::Dynamic<String>) -> Self {
        let val = <crate::Dynamic<String> as crate::RevealSecret>::expose_secret(&d).clone();
        Secret::new(val)
    }
}

/// Converts `Secret<Vec<T>>` into a [`Dynamic<Vec<T>>`](crate::Dynamic).
impl<T: Clone + Zeroize + 'static> From<Secret<Vec<T>>> for crate::Dynamic<Vec<T>> {
    fn from(s: Secret<Vec<T>>) -> Self {
        crate::Dynamic::new(s.inner_secret.clone())
    }
}

/// Converts a [`Dynamic<Vec<T>>`](crate::Dynamic) into `Secret<Vec<T>>`.
impl<T: Clone + Zeroize + 'static> From<crate::Dynamic<Vec<T>>> for Secret<Vec<T>> {
    fn from(d: crate::Dynamic<Vec<T>>) -> Self {
        let val = <crate::Dynamic<Vec<T>> as crate::RevealSecret>::expose_secret(&d).clone();
        Secret::new(val)
    }
}

/// Converts `Secret<[T; N]>` into a [`Fixed<[T; N]>`](crate::Fixed).
impl<T: Clone + Zeroize, const N: usize> From<Secret<[T; N]>> for crate::Fixed<[T; N]> {
    fn from(s: Secret<[T; N]>) -> Self {
        let arr = s.inner_secret.clone();
        crate::Fixed::new(arr)
    }
}

/// Converts a [`Fixed<[T; N]>`](crate::Fixed) into `Secret<[T; N]>`.
impl<T: Clone + Zeroize, const N: usize> From<crate::Fixed<[T; N]>> for Secret<[T; N]> {
    fn from(f: crate::Fixed<[T; N]>) -> Self {
        let arr = crate::RevealSecret::expose_secret(&f).clone();
        Secret::new(arr)
    }
}
