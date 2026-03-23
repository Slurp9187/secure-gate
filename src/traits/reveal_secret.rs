//! Traits for controlled, polymorphic secret revelation.
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
//! | [`RevealSecret`]                | Read-only  | `with_secret` (scoped)    | `expose_secret`     | `len`, `is_empty` | Always |
//! | [`crate::RevealSecretMut`]      | Mutable    | `with_secret_mut` (scoped)| `expose_secret_mut` | Inherits above    | Always |
//!
//! # Security Model
//!
//! - **Core wrappers** (`Fixed<T>`, `Dynamic<T>`) implement both traits → full access.
//! - **Read-only wrappers** (encoding wrappers, random types) implement only `RevealSecret` → mutation prevented.
//! - **Zero-cost** — all methods are `#[inline(always)]` where possible.
//! - **Scoped access preferred** — `with_secret` / `with_secret_mut` limit borrow lifetime, reducing leak risk.
//! - **Direct exposure** (`expose_secret` / `expose_secret_mut`) is provided for legitimate needs (FFI, third-party APIs), but marked as an escape hatch.
//!
//! # Usage Guidelines
//!
//! The preferred and recommended way to access secrets is the scoped `with_secret` /
//! `with_secret_mut` methods. `expose_secret` / `expose_secret_mut` are escape hatches
//! for rare cases and should be audited closely.
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
//! use secure_gate::{Fixed, RevealSecret};
//!
//! let secret = Fixed::new([42u8; 4]);
//! let sum: u32 = secret.with_secret(|bytes| bytes.iter().map(|&b| b as u32).sum());
//! assert_eq!(sum, 42 * 4);
//! ```
//!
//! Direct (escape hatch – use with caution):
//!
//! ```rust
//! use secure_gate::{Fixed, RevealSecret};
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
//! use secure_gate::{Fixed, RevealSecret, RevealSecretMut};
//!
//! let mut secret = Fixed::new([0u8; 4]);
//! secret.with_secret_mut(|bytes| bytes[0] = 99);
//! assert_eq!(secret.expose_secret()[0], 99);
//! ```
//!
//! Polymorphic generic code:
//!
//! ```rust
//! use secure_gate::RevealSecret;
//!
//! fn print_length<S: RevealSecret>(secret: &S) {
//!     println!("Length: {} bytes", secret.len());
//! }
//! ```
//!
//! These traits are the foundation of secure-gate's security model: all secret access is
//! explicit, auditable, and controlled. Prefer scoped methods in nearly all cases.
//!
//! # Implementation Notes
//!
//! Long-lived `expose_secret()` references can defeat scoping — the borrow outlives the
//! call site and the compiler cannot enforce that the secret is not retained. This is an
//! intentional escape hatch for FFI and legacy APIs; audit every call site.

/// Read-only access to a wrapped secret.
///
/// Implemented by [`Fixed<T>`](crate::Fixed) and [`Dynamic<T>`](crate::Dynamic).
/// Prefer the scoped [`with_secret`](Self::with_secret) method; use
/// [`expose_secret`](Self::expose_secret) only when a long-lived reference is
/// unavoidable. See [`RevealSecretMut`](crate::RevealSecretMut) for the mutable
/// counterpart.
pub trait RevealSecret {
    /// The inner secret type being revealed.
    ///
    /// This can be a sized type (e.g. `[u8; N]`, `u32`) or unsized (e.g. `str`, `[u8]`).
    type Inner: ?Sized;

    /// Provides scoped (recommended) read-only access to the secret.
    ///
    /// The closure receives a reference that cannot escape — the borrow ends when
    /// the closure returns, minimizing the lifetime of the exposed secret.
    /// Prefer this over [`expose_secret`](Self::expose_secret) in all application code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// let secret = Fixed::new([42u8; 4]);
    /// let sum: u32 = secret.with_secret(|bytes| bytes.iter().map(|&b| b as u32).sum());
    /// assert_eq!(sum, 42 * 4);
    /// ```
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Self::Inner) -> R;

    /// Returns a direct (auditable) read-only reference to the secret.
    ///
    /// Long-lived `expose_secret()` references can defeat scoping — prefer
    /// [`with_secret`](Self::with_secret) in application code. Use this only when
    /// a long-lived reference is unavoidable (e.g. FFI, third-party APIs).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// let secret = Fixed::new([42u8; 4]);
    ///
    /// // Auditable escape hatch — FFI use case:
    /// // unsafe { c_fn(secret.expose_secret().as_ptr(), secret.len()); }
    /// let _ = secret.expose_secret();
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
