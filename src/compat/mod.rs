//! secrecy compatibility layers — drop-in replacements for the `secrecy` crate.
//!
//! Enable with `features = ["secrecy-compat"]` in your `Cargo.toml`.
//!
//! Two sub-modules mirror the two most-deployed secrecy generations:
//!
//! | Module | secrecy version | Key type |
//! |---|---|---|
//! | [`v10`] | 0.10.1 (`SecretBox<S>`, heap-alloc) | `SecretBox<str>` for strings |
//! | [`v08`] | 0.8.0 (`Secret<S>`, stack/inline) | `Secret<String>` for strings |
//!
//! ## Shared surface (re-exported from this module)
//!
//! | Item | Purpose |
//! |---|---|
//! | [`ExposeSecret`] | Read-only access trait (both versions) |
//! | [`ExposeSecretMut`] | Mutable access trait (v0.10+) |
//! | [`CloneableSecret`] | Clone opt-in marker (both versions) |
//! | [`SerializableSecret`] | Serialize opt-in marker (both versions) |
//! | [`zeroize`] | Re-exported `zeroize` crate (mirrors `secrecy`'s own re-export) |
//!
//! ## Quick-start migration
//!
//! **From secrecy 0.10.x:**
//!
//! ```text
//! // Before
//! use secrecy::{SecretBox, SecretString, ExposeSecret};
//!
//! // After (one global find/replace)
//! use secure_gate::compat::v10::{SecretBox, SecretString};
//! use secure_gate::compat::ExposeSecret;
//! ```
//!
//! **From secrecy 0.8.x:**
//!
//! ```text
//! // Before
//! use secrecy::{Secret, SecretString, DebugSecret, ExposeSecret};
//!
//! // After (one global find/replace)
//! use secure_gate::compat::v08::{Secret, SecretString, DebugSecret};
//! use secure_gate::compat::ExposeSecret;
//! ```
//!
//! ## Bridge impls
//!
//! Native [`Dynamic<T>`](crate::Dynamic) and [`Fixed<[T; N]>`](crate::Fixed) implement
//! both [`ExposeSecret`] and [`ExposeSecretMut`] so that code written against the secrecy
//! traits compiles unchanged when you swap the concrete type for a native secure-gate type.

extern crate alloc;

use zeroize::Zeroize;

// ── zeroize re-export ────────────────────────────────────────────────────────

/// Re-exported [`zeroize`] crate — mirrors `secrecy`'s own `pub use zeroize;`.
///
/// Allows `use secrecy::zeroize::Zeroize` to migrate unchanged via
/// `use secure_gate::compat::zeroize::Zeroize`.
pub use zeroize;

// ── ExposeSecret / ExposeSecretMut ───────────────────────────────────────────

/// Read-only access to a wrapped secret — mirrors `secrecy::ExposeSecret`.
///
/// Implemented directly by [`v08::Secret`] and [`v10::SecretBox`], and by bridge
/// impls on [`Dynamic<String>`](crate::Dynamic), [`Dynamic<Vec<T>>`](crate::Dynamic),
/// and [`Fixed<[T; N]>`](crate::Fixed).
///
/// # Migration
///
/// For new code, prefer [`RevealSecret`](crate::RevealSecret), which additionally provides
/// scoped `with_secret` access and byte-length metadata.
pub trait ExposeSecret<S: ?Sized> {
    /// Returns a shared reference to the inner secret.
    fn expose_secret(&self) -> &S;
}

/// Mutable access to a wrapped secret — mirrors `secrecy::ExposeSecretMut`.
///
/// Added in secrecy 0.9. Not implemented for [`v08::Secret`] (which is read-only by design
/// in that era). Implemented for [`v10::SecretBox`] and bridge impls on native types.
///
/// # Migration
///
/// For new code, prefer [`RevealSecretMut`](crate::RevealSecretMut).
pub trait ExposeSecretMut<S: ?Sized> {
    /// Returns a mutable reference to the inner secret.
    fn expose_secret_mut(&mut self) -> &mut S;
}

// ── CloneableSecret ──────────────────────────────────────────────────────────

/// Marker trait for secrets that may be cloned — mirrors `secrecy::CloneableSecret`.
///
/// Defined here (rather than behind the `cloneable` feature) so the compat layer
/// works without requiring callers to enable that feature flag.
///
/// For native secure-gate code, enable the `cloneable` feature and use
/// [`secure_gate::CloneableSecret`](crate::CloneableSecret) directly.
pub trait CloneableSecret: Clone + Zeroize {}

impl CloneableSecret for i8 {}
impl CloneableSecret for i16 {}
impl CloneableSecret for i32 {}
impl CloneableSecret for i64 {}
impl CloneableSecret for i128 {}
impl CloneableSecret for isize {}
impl CloneableSecret for u8 {}
impl CloneableSecret for u16 {}
impl CloneableSecret for u32 {}
impl CloneableSecret for u64 {}
impl CloneableSecret for u128 {}
impl CloneableSecret for usize {}
impl<Z: CloneableSecret, const N: usize> CloneableSecret for [Z; N] {}

// ── SerializableSecret ───────────────────────────────────────────────────────

/// Marker trait for secrets that may be serialized — mirrors `secrecy::SerializableSecret`.
///
/// Re-exports [`crate::SerializableSecret`] so that code importing from the compat layer
/// obtains the **same** trait as code importing from the crate root, preventing
/// disambiguation issues in compiler error messages.
///
/// Requires the `serde-serialize` feature. Serialization of secret wrappers is
/// deliberately opt-in to prevent accidental exfiltration.
#[cfg(feature = "serde-serialize")]
pub use crate::SerializableSecret;

// ── Bridge: secure-gate native types → ExposeSecret / ExposeSecretMut ────────
//
// These explicit impls allow code written against the secrecy `ExposeSecret` trait
// to compile unchanged with native `Dynamic<T>` and `Fixed<[T; N]>` values.
//
// Explicit (rather than blanket) impls prevent the blanket from also catching
// `SecretBox` / `Secret`, which carry their own direct impls.

impl ExposeSecret<alloc::string::String> for crate::Dynamic<alloc::string::String> {
    #[inline]
    fn expose_secret(&self) -> &alloc::string::String {
        crate::RevealSecret::expose_secret(self)
    }
}

impl ExposeSecretMut<alloc::string::String> for crate::Dynamic<alloc::string::String> {
    #[inline]
    fn expose_secret_mut(&mut self) -> &mut alloc::string::String {
        crate::RevealSecretMut::expose_secret_mut(self)
    }
}

impl<T: Zeroize> ExposeSecret<alloc::vec::Vec<T>> for crate::Dynamic<alloc::vec::Vec<T>> {
    #[inline]
    fn expose_secret(&self) -> &alloc::vec::Vec<T> {
        crate::RevealSecret::expose_secret(self)
    }
}

impl<T: Zeroize> ExposeSecretMut<alloc::vec::Vec<T>> for crate::Dynamic<alloc::vec::Vec<T>> {
    #[inline]
    fn expose_secret_mut(&mut self) -> &mut alloc::vec::Vec<T> {
        crate::RevealSecretMut::expose_secret_mut(self)
    }
}

impl<const N: usize, T: Zeroize> ExposeSecret<[T; N]> for crate::Fixed<[T; N]> {
    #[inline]
    fn expose_secret(&self) -> &[T; N] {
        crate::RevealSecret::expose_secret(self)
    }
}

impl<const N: usize, T: Zeroize> ExposeSecretMut<[T; N]> for crate::Fixed<[T; N]> {
    #[inline]
    fn expose_secret_mut(&mut self) -> &mut [T; N] {
        crate::RevealSecretMut::expose_secret_mut(self)
    }
}

// ── Sub-modules ───────────────────────────────────────────────────────────────

/// secrecy **v0.10.1** compatibility — heap-allocated `SecretBox<S>`.
///
/// Mirrors secrecy 0.10.1 exactly (edition 2021, rust-version 1.60).
/// See the [module docs](v10) for a per-item migration guide.
pub mod v10;

/// secrecy **v0.8.0** compatibility — inline/stack-allocated `Secret<S>`.
///
/// Mirrors secrecy 0.8.0 (edition 2018, no const-generic arrays).
/// See the [module docs](v08) for a per-item migration guide.
pub mod v08;
