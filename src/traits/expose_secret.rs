//! Traits for controlled, polymorphic secret exposure.
//!
//! This module defines the core traits that enforce explicit, auditable access to
//! secret data across all wrapper types (`Fixed<T>`, `Dynamic<T>`, aliases, etc.).
//!
//! The design ensures:
//! - No implicit borrowing (`Deref`, `AsRef`, etc.)
//! - Scoped access is preferred (minimizes lifetime of exposed references)
//! - Direct exposure is possible but clearly marked as an escape hatch
//! - Metadata (`len`, `is_empty`) is always available without full exposure
//!
//! # Key Traits
//!
//! | Trait                  | Access     | Preferred Method          | Escape Hatch             | Metadata          | Feature     |
//! |------------------------|------------|---------------------------|--------------------------|-------------------|-------------|
//! | [`ExposeSecret`]       | Read-only  | `with_secret` (scoped)    | `expose_secret`          | `len`, `is_empty` | Always      |
//! | [`ExposeSecretMut`]    | Mutable    | `with_secret_mut` (scoped)| `expose_secret_mut`      | Inherits from above | Always      |
//!
//! # Security Model
//!
//! - **Core wrappers** (`Fixed<T>`, `Dynamic<T>`) implement both traits → full access.
//! - **Read-only wrappers** (encoding wrappers, random types) implement only `ExposeSecret` → mutation prevented.
//! - **Zero-cost** — all methods are `#[inline(always)]` where possible.
//! - **Scoped access preferred** — `with_secret` / `with_secret_mut` limit borrow lifetime, reducing leak risk.
//! - **Direct exposure** (`expose_secret` / `expose_secret_mut`) is provided for legitimate needs (FFI, third-party APIs), but marked as an escape hatch.
//!
//! # Usage Guidelines
//!
//! - **Always prefer scoped methods** (`with_secret`, `with_secret_mut`) in application code.
//! - Use direct exposure only when necessary (e.g., passing raw pointer + length to C FFI).
//! - Audit every `expose_secret*` call — they should be rare and well-justified.
//!
//! # Examples
//!
//! Scoped (recommended):
//!
//! ```rust
//! use secure_gate::{Fixed, ExposeSecret};
//!
//! let secret = Fixed::new([42u8; 4]);
//! let sum: u32 = secret.with_secret(|bytes| bytes.iter().map(|&b| b as u32).sum());
//! assert_eq!(sum, 42 * 4);
//! ```
//!
//! Direct (escape hatch – use with caution):
//!
//! ```rust
//! use secure_gate::{Fixed, ExposeSecret};
//!
//! let secret = Fixed::new([42u8; 4]);
//!
//! // Example: FFI call needing raw pointer + length
//! // unsafe {
//! //     c_function(secret.expose_secret().as_ptr(), secret.len());
//! // }
//! ```
//!
//! Mutable scoped:
//!
//! ```rust
//! use secure_gate::{Fixed, ExposeSecret, ExposeSecretMut};
//!
//! let mut secret = Fixed::new([0u8; 4]);
//! secret.with_secret_mut(|bytes| bytes[0] = 99);
//! assert_eq!(secret.expose_secret()[0], 99);
//! ```
//!
//! Polymorphic generic code:
//!
//! ```rust
//! use secure_gate::ExposeSecret;
//!
//! fn print_length<S: ExposeSecret>(secret: &S) {
//!     println!("Length: {} bytes", secret.len());
//! }
//! ```
//!
//! These traits are the foundation of secure-gate's security model: all secret access is
//! explicit, auditable, and controlled. Prefer scoped methods in nearly all cases.
pub trait ExposeSecret {
    /// The inner secret type being exposed.
    ///
    /// This can be a sized type (e.g. `[u8; N]`, `u32`) or unsized (e.g. `str`, `[u8]`).
    type Inner: ?Sized;

    /// Provides scoped read-only access to the secret.
    ///
    /// **This is the preferred method** for accessing secrets.
    /// The closure receives a reference to the inner secret and returns a value.
    /// The borrow ends when the closure returns, minimizing exposure time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, ExposeSecret};
    ///
    /// let secret = Fixed::new([42u8; 4]);
    /// let sum: u32 = secret.with_secret(|bytes| bytes.iter().map(|&b| b as u32).sum());
    /// assert_eq!(sum, 42 * 4);
    /// ```
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Self::Inner) -> R;

    /// Exposes the secret for read-only access.
    ///
    /// See [`ExposeSecret`] for the full security model and scoping recommendations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::Fixed;
    ///
    /// let secret = Fixed::new([42u8; 4]);
    ///
    /// // Typical FFI use case (direct reference needed)
    /// // unsafe {
    /// //     c_library_function(secret.expose_secret().as_ptr(), secret.len());
    /// // }
    /// ```
    fn expose_secret(&self) -> &Self::Inner;

    /// Returns the length of the secret in bytes.
    ///
    /// Always safe to call — does not expose secret contents.
    fn len(&self) -> usize;

    /// Returns `true` if the secret is empty.
    ///
    /// Always safe to call — does not expose secret contents.
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
