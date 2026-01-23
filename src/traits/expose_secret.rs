//! # Secret Exposure Traits
//!
//! This module defines traits for polymorphic secret access with controlled mutability and metadata.
//! These traits enable writing generic code that works across different secret wrapper types
//! while enforcing security guarantees.
//!
//! ## Key Traits
//!
//! - [`ExposeSecret`]: Read-only access to secret values including metadata
//!
//! ## Security Model
//!
//! - **Full access**: Core wrappers ([`crate::Fixed`], [`crate::Dynamic`]) implement [`ExposeSecret`], with mutable variants implementing [`ExposeSecretMut`]
//! - **Read-only**: Encoding wrappers only implement [`ExposeSecret`] to prevent mutation
//! - **Zero-cost**: All implementations use `#[inline(always)]`
//!
/// Trait for read-only access to secrets, including metadata.
///
/// ## Usage
///
/// Import these traits to access secret values and their metadata ergonomically.
///
/// Import this to enable `.with_secret()`, `.expose_secret()`, `.len()`, and `.is_empty()`.
/// For mutable access, see [`crate::ExposeSecretMut`].
///
/// ## Security Note
///
/// Prefer `with_secret` for scoped access to avoid accidental leaks through long-lived borrows.
/// `expose_secret` is provided for cases where a direct reference is needed, but use with caution.
pub trait ExposeSecret {
    /// The inner secret type being exposed.
    ///
    /// This can be a sized type (like `[u8; N]`) or unsized (like `str` or `[u8]`).
    type Inner: ?Sized;

    /// Provide scoped read-only access to the secret.
    ///
    /// This is the preferred method for accessing secrets, as it prevents accidental leaks
    /// through long-lived borrows. The closure receives a reference to the inner secret
    /// and returns a value.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::{Fixed, ExposeSecret};
    /// let secret = Fixed::new([42u8; 4]);
    /// let sum: u32 = secret.with_secret(|bytes| bytes.iter().map(|&b| b as u32).sum());
    /// assert_eq!(sum, 42 * 4);
    /// ```
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Self::Inner) -> R;

    /// Expose the secret for read-only access.
    ///
    /// # Security Warning
    ///
    /// This returns a direct reference that can be accidentally leaked. Prefer `with_secret`
    /// for most use cases to ensure the secret is only accessed within a controlled scope.
    fn expose_secret(&self) -> &Self::Inner;

    /// Returns the length of the secret.
    fn len(&self) -> usize;

    /// Returns true if the secret is empty.
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
