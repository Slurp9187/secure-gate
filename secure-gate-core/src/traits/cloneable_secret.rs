//! Opt-in marker trait for safe, explicit cloning of secrets.
//!
//! This trait serves as a deliberate opt-in mechanism to enable the `Clone`
//! implementation on secret wrapper types (`Fixed<T>`, `Dynamic<T>`, aliases)
//! while preserving core security invariants:
//!
//! - **Zeroization preserved**: All clones zeroize their contents on drop.
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
//! # A newtype inner type is required (orphan rule)
//!
//! Rust's coherence (orphan) rules prevent downstream crates from implementing
//! this marker for foreign types: `impl CloneableSecret for String`,
//! `Vec<u8>`, or `[u8; 32]` does **not compile** outside this crate, because
//! both the trait and the type would be foreign. Consequently `Dynamic<String>`,
//! `Dynamic<Vec<u8>>`, and `Fixed<[u8; N]>` can never be cloned directly.
//!
//! This is deliberate, not an oversight: if the marker were pre-implemented for
//! the standard container types, enabling the `cloneable` feature would silently
//! make *every* `Dynamic<String>` in a dependency graph cloneable. Requiring a
//! local newtype (as in the example below) keeps each cloneable secret type
//! defined — and auditable — in your own code.
//!
//! # Example
//!
//! ```rust
//! use secure_gate::{CloneableSecret, Fixed, RevealSecret};
//! use zeroize::Zeroize;
//!
//! #[derive(Clone)]
//! struct SessionKey([u8; 32]);
//!
//! impl Zeroize for SessionKey {
//!     fn zeroize(&mut self) { self.0.zeroize(); }
//! }
//!
//! // Every impl is a deliberate security decision — audit all usages.
//! impl CloneableSecret for SessionKey {}
//!
//! let original = Fixed::new(SessionKey([0u8; 32]));
//! let copy = original.clone();   // Opt-in cloning: each copy is independently zeroized.
//! drop(original);  // zeroized on drop
//! drop(copy);      // independently zeroized on drop
//! ```
//!
//! # Security Notes
//!
//! - Cloning **does not** bypass zeroization — **every** copy is independently zeroized on drop.
//!   However, each clone **increases the number of simultaneous in-memory copies**, expanding
//!   the window for memory-extraction attacks (cold-boot, scraping, etc.).
//! - Audit all `CloneableSecret` impls to ensure the inner type correctly implements
//!   `Clone` and `Zeroize`.
//!
//! This trait is a **marker only** — it has no methods and adds no runtime behavior.
//! It exists solely to gate the `Clone` impl on wrapper types.
#[cfg(feature = "cloneable")]
/// Marker trait: inner types that opt in to cloning secret wrappers (requires `cloneable`).
pub trait CloneableSecret: Clone + zeroize::Zeroize {}
