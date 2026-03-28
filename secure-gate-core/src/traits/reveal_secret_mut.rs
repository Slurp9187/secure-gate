//! Traits for mutable secret revelation.
//!
//! This module defines the [`RevealSecretMut`] trait, which extends
//! [`RevealSecret`] to provide controlled mutable access to secrets.
//!
//! Only the core secret wrappers (`Fixed<T>` and `Dynamic<T>`) implement this
//! trait. Read-only wrappers (e.g., encoding types, random generators) deliberately
//! **do not** implement it to prevent accidental mutation.
//!
//! # Security Model
//!
//! - **Scoped mutation preferred**: `with_secret_mut` limits the mutable borrow
//!   to the closure lifetime, minimizing exposure risk.
//! - **Direct mutable exposure** (`expose_secret_mut`) is an explicit escape hatch
//!   for legitimate needs (e.g., FFI, third-party APIs that require `&mut T`).
//! - **Zero-cost**: All methods use `#[inline(always)]` where appropriate.
//! - **Inheritance**: You automatically get `.len()`, `.is_empty()`, `with_secret`,
//!   and `expose_secret` from [`RevealSecret`].
//! - **No implicit leaks**: No `DerefMut`, `AsMut`, or accidental borrowing.
//!
//! # Usage Guidelines
//!
//! The preferred and recommended way to access secrets is the scoped `with_secret` /
//! `with_secret_mut` methods. `expose_secret` / `expose_secret_mut` are escape hatches
//! for rare cases and should be audited closely.
//!
//! - Prefer scoped methods (`with_secret_mut`) in application code.
//! - Use `expose_secret_mut` **only** when you need a long-lived mutable reference
//!   (e.g., passing raw pointer to C FFI or interfacing with legacy APIs).
//! - Audit every `expose_secret_mut` call — they should be rare and well-justified.
//!
//! # Examples
//!
//! Scoped mutable access (recommended):
//!
//! ```rust
//! use secure_gate::{Fixed, RevealSecretMut, RevealSecret};
//!
//! let mut secret = Fixed::new([0u8; 4]);
//! secret.with_secret_mut(|bytes| bytes[0] = 42);
//! assert_eq!(secret.expose_secret()[0], 42);
//! ```
//!
//!
//! Polymorphic generic code (works for any mutable secret wrapper):
//!
//! ```rust
//! use secure_gate::RevealSecretMut;
//!
//! fn mutate_first_byte<S: RevealSecretMut>(secret: &mut S)
//! where
//!     S::Inner: AsMut<[u8]>,
//! {
//!     secret.with_secret_mut(|bytes| {
//!         if let Some(first) = bytes.as_mut().first_mut() {
//!             *first = 99;
//!         }
//!     });
//! }
//! ```
//!
//! This trait (together with [`RevealSecret`]) enforces the core security principle of secure-gate:
//! **all secret access (read or write) must be explicit and auditable**.
//! Scoped methods are preferred in nearly all cases.
use crate::RevealSecret;

/// Trait for mutable access to secrets.
///
/// Extends [`RevealSecret`] (so you get read-only access, `len()`, `is_empty()`, etc.).
/// Only core wrappers (`Fixed<T>`, `Dynamic<T>`) implement this trait.
pub trait RevealSecretMut: RevealSecret {
    /// Provides scoped (recommended) mutable access to the secret.
    ///
    /// The closure receives a `&mut` reference that cannot escape — the borrow ends
    /// when the closure returns, minimizing the mutable exposure window.
    /// Prefer this over [`expose_secret_mut`](Self::expose_secret_mut).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, RevealSecretMut, RevealSecret};
    ///
    /// let mut secret = Fixed::new([0u8; 4]);
    /// secret.with_secret_mut(|bytes| bytes[0] = 42);
    /// assert_eq!(secret.expose_secret()[0], 42);
    /// ```
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Self::Inner) -> R;

    /// Returns a direct (auditable) mutable reference to the secret.
    ///
    /// Long-lived mutable references can defeat scoping — prefer
    /// [`with_secret_mut`](Self::with_secret_mut) in application code.
    fn expose_secret_mut(&mut self) -> &mut Self::Inner;
}
