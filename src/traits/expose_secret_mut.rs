//! # Mutable Secret Exposure Traits
//!
//! This module defines the trait for mutable access to secrets.
//!
//! ## Key Traits
//!
//! - [`ExposeSecretMut`]: Mutable access to secret values
//!
//! ## Security Model
//!
//! - **Mutable access**: Only core wrappers ([`crate::Fixed`], [`crate::Dynamic`]) implement [`ExposeSecretMut`]
//! - **Zero-cost**: All implementations use `#[inline(always)]`
use super::ExposeSecret;

/// ## Usage
///
/// Import this trait to enable `.with_secret_mut()` and `.expose_secret_mut()`.
/// Extends [`ExposeSecret`], so read access and metadata are also available.
/// Trait for mutable access to secrets.
///
/// Extends [`ExposeSecret`], so metadata and read access are included.
/// Import this for `.with_secret_mut()` and `.expose_secret_mut()`.
///
/// ## Security Note
///
/// Prefer `with_secret_mut` for scoped access to avoid accidental leaks through long-lived borrows.
/// `expose_secret_mut` is provided for cases where a direct mutable reference is needed, but use with caution.
pub trait ExposeSecretMut: ExposeSecret {
    /// Provide scoped mutable access to the secret.
    ///
    /// This is the preferred method for mutating secrets, as it prevents accidental leaks
    /// through long-lived mutable borrows. The closure receives a mutable reference to the inner secret
    /// and returns a value.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::{Fixed, ExposeSecretMut};
    /// let mut secret = Fixed::new([0u8; 4]);
    /// secret.with_secret_mut(|bytes| {
    ///     bytes[0] = 42;
    /// });
    /// ```
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Self::Inner) -> R;

    /// Expose the secret for mutable access.
    ///
    /// # Security Warning
    ///
    /// This returns a direct mutable reference that can be accidentally leaked. Prefer `with_secret_mut`
    /// for most use cases to ensure the secret is only mutated within a controlled scope.
    fn expose_secret_mut(&mut self) -> &mut Self::Inner;
}
