//! Opt-in marker trait for safe, explicit cloning of secrets.
//!
//! This trait serves as a deliberate opt-in mechanism to enable the `Clone`
//! implementation on secret wrapper types (`Fixed<T>`, `Dynamic<T>`, aliases)
//! while preserving core security invariants:
//!
//! - **Zeroization preserved**: All clones zeroize their contents on drop (when
//!   the `zeroize` feature is enabled).
//! - **No accidental cloning**: Cloning is impossible unless the inner type
//!   explicitly implements `CloneableSecret`.
//! - **Auditable risk**: Cloning increases the exposure surface (more copies
//!   of the secret exist in memory); this trait forces developers to acknowledge
//!   and accept that risk.
//!
//! Requires the `cloneable` feature to be enabled.
//!
//! # When to Use
//!
//! Implement `CloneableSecret` on inner types only when duplication is
//! **truly necessary** (e.g., session keys passed to multiple threads,
//! backup/export scenarios). Prefer move semantics or single-instance ownership
//! whenever possible to minimize attack surface.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "cloneable")]
//! use secure_gate::{CloneableSecret, Fixed};
//! # #[cfg(feature = "cloneable")]
//! use zeroize::Zeroize;
//!
//! # #[cfg(feature = "cloneable")]
//! {
//! #[derive(Clone)]
//! struct SessionKey([u8; 32]);
//!
//! impl Zeroize for SessionKey {
//!     fn zeroize(&mut self) {
//!         self.0.zeroize();
//!     }
//! }
//!
//! impl CloneableSecret for SessionKey {}
//!
//! let original = Fixed::new(SessionKey([0; 32]));
//! let copy = original.clone();           // Cloning now allowed
//! assert_eq!(original.expose_secret().0, copy.expose_secret().0);
//! # }
//! ```
//!
//! # Security Notes
//!
//! - Cloning **does not** bypass zeroization — every copy is independently zeroized.
//! - Use `CloneableSecret` sparingly; each clone increases the number of in-memory
//!   copies of the secret, expanding the window for extraction attacks.
//! - Audit all `CloneableSecret` impls to ensure the inner type correctly implements
//!   `Clone` and `Zeroize` (if `zeroize` is enabled).
//!
//! This trait is a **marker only** — it has no methods and adds no runtime behavior.
//! It exists solely to gate the `Clone` impl on wrapper types.
#[cfg(feature = "cloneable")]
pub trait CloneableSecret: Clone {}
