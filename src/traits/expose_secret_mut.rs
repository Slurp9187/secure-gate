//! Traits for mutable secret exposure.
//!
//! This module defines the [`ExposeSecretMut`] trait, which extends
//! [`ExposeSecret`] to provide controlled mutable access to secrets.
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
//!   and `expose_secret` from [`ExposeSecret`].
//! - **No implicit leaks**: No `DerefMut`, `AsMut`, or accidental borrowing.
//!
//! # Usage Guidelines
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
//! use secure_gate::{Fixed, ExposeSecretMut, ExposeSecret};
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
//! use secure_gate::ExposeSecretMut;
//!
//! fn mutate_first_byte<S: ExposeSecretMut>(secret: &mut S) where S::Inner: AsMut<[u8]> {
//!     secret.with_secret_mut(|bytes| {
//!         if let Some(first) = bytes.as_mut().first_mut() {
//!             *first = 99;
//!         }
//!     });
//! }
//! ```
//!
//! These traits enforce the core security principle of secure-gate:
//! **all secret access (read or write) must be explicit and auditable**.
//! Scoped methods are preferred in nearly all cases.
use crate::ExposeSecret;

/// Trait for mutable access to secrets.
///
/// Extends [`ExposeSecret`] (so you get read-only access, `len()`, `is_empty()`, etc.).
/// Only core wrappers (`Fixed<T>`, `Dynamic<T>`) implement this trait.
pub trait ExposeSecretMut: ExposeSecret {
    /// Provides scoped mutable access to the secret.
    ///
    /// **This is the preferred method** for mutating secrets.
    /// The closure receives a mutable reference to the inner secret and returns a value.
    /// The borrow ends when the closure returns, minimizing exposure time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecretMut};
    ///
    /// let mut secret = Fixed::new([0u8; 4]);
    /// secret.with_secret_mut(|bytes| bytes[0] = 42);
    /// ```
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Self::Inner) -> R;

    /// Exposes the secret for mutable access.
    ///
    /// See [`ExposeSecretMut`] for the full security model and scoping recommendations.
    fn expose_secret_mut(&mut self) -> &mut Self::Inner;
}
