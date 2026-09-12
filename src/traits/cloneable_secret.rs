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
//! The pattern is fully supported: [`RevealSecret`](crate::RevealSecret) and
//! [`RevealSecretMut`](crate::RevealSecretMut) are implemented for **every**
//! inner type, so a `Fixed<SessionKey>` built this way is readable, mutable,
//! and (with a [`ConstantTimeEq`](crate::ConstantTimeEq) impl on the inner
//! type) comparable — not just cloneable. Only
//! [`SecretLen`](crate::SecretLen) stays narrow, since a custom inner type has
//! no meaningful length.
//!
//! # Example
//!
//! ```rust
//! use secure_gate::{CloneableSecret, Fixed, FixedStorage, RevealSecret};
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
//! // Required by `Fixed::new`: asserts this type owns no buffer that can be reallocated.
//! impl FixedStorage for SessionKey {}
//!
//! let original = Fixed::new(SessionKey([0u8; 32]));
//! let copy = original.clone();   // Opt-in cloning: each copy is independently zeroized.
//! drop(original);  // zeroized on drop
//! drop(copy);      // independently zeroized on drop
//! ```
//!
//! # One diagnostic that points the wrong way
//!
//! If you call `.clone()` on a **reference** to a wrapper whose inner type lacks this
//! marker, and you do not annotate the target type, the call resolves to
//! `<&T as Clone>::clone` instead. It compiles, copies the reference rather than the
//! secret, and produces rustc's `noop_method_call` warning — whose `help:` suggests
//! adding `#[derive(Clone)]` to `Dynamic`, which is to say it suggests deleting this gate:
//!
//! ```text
//! warning: call to `.clone()` on a reference in this situation does nothing
//!    = note: the type `Dynamic<Vec<u8>>` does not implement `Clone`, so calling `clone`
//!            on `&Dynamic<Vec<u8>>` copies the reference, which does not do anything
//! help: if you meant to clone `Dynamic<Vec<u8>>`, implement `Clone` for it
//! 184 + #[derive(Clone)]
//! ```
//!
//! Nothing is duplicated, so no secret escapes — the opposite, the call does nothing at
//! all. It is recorded here because the suggested fix is wrong for this crate and a reader
//! who follows it removes the opt-in. The gate itself still holds: an owned receiver, or
//! an annotated target, gives the real error instead —
//! `error[E0277]: the trait bound ... CloneableSecret is not satisfied`.
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
