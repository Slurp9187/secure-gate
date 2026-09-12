//! Opt-in marker trait for safe, explicit Serde serialization of secrets.
//!
//! This trait acts as a deliberate security gate: it enables `Serialize` on secret
//! wrapper types (`Fixed<T>`, `Dynamic<T>`, aliases) **only** when the inner type
//! explicitly opts in. It gates `Serialize` and nothing else — the trait is declared
//! `pub trait SerializableSecret: serde::Serialize {}`. `Deserialize` is independent
//! of this marker; see the note below.
//!
//! Requires the `serde-serialize` feature.
//!
//! # Security Properties
//!
//! - **No automatic exposure** — Serialization is impossible unless the inner type
//!   implements `SerializableSecret`.
//! - **Explicit risk acceptance** — Cloning/serialization increases the chance of
//!   secret leakage (e.g., via logs, network, disk). This marker forces developers
//!   to acknowledge and accept that risk.
//! - **Zeroization preserved in the wrapper** — serializing does not bypass
//!   `ZeroizeOnDrop` for the wrapper itself. It says nothing about the output: the
//!   bytes the serializer writes to a buffer, socket or file are ordinary
//!   non-zeroizing memory this crate cannot reach.
//! - **This marker does not gate `Deserialize`** — deserialization is enabled by the
//!   `serde-deserialize` feature alone, and implementing `SerializableSecret` neither
//!   enables nor restricts it. Implementing the marker is not a statement about
//!   deserialization safety.
//!
//! # When to Use
//!
//! Implement `SerializableSecret` **only** when serialization is **truly necessary**:
//!
//! - Encrypted backups of keys/tokens
//! - Secure export for cross-process or cross-device transfer
//! - Persistent storage in encrypted form
//!
//! Prefer **non-serializable designs** wherever possible:
//! - Derive keys on-the-fly from a master secret
//! - Use ephemeral in-memory secrets
//! - Avoid persisting raw secrets at all
//!
//! # A newtype inner type is required (orphan rule)
//!
//! Rust's coherence (orphan) rules prevent downstream crates from implementing
//! this marker for foreign types: `impl SerializableSecret for String`,
//! `Vec<u8>`, or `[u8; 32]` does **not compile** outside this crate, because
//! both the trait and the type would be foreign. Consequently `Fixed<[u8; N]>`,
//! `Dynamic<String>`, and `Dynamic<Vec<u8>>` can never be serialized directly.
//!
//! This is deliberate, not an oversight: if the marker were pre-implemented for
//! the standard container types, enabling the `serde-serialize` feature would
//! silently make *every* wrapped secret in a dependency graph serializable.
//! Requiring a local newtype (as in the example below) keeps each serializable
//! secret type defined — and auditable — in your own code.
//!
//! (`Deserialize` is unaffected: it is implemented on the wrapper types
//! directly, gated by the `serde-deserialize` feature, because deserialization
//! *constructs* a protected secret rather than exposing one.)
//!
//! # Example
//!
//! ```rust
//! use secure_gate::{Dynamic, SerializableSecret};
//! use serde::{Serialize, Deserialize};
//! use zeroize::Zeroize;
//!
//! #[derive(Serialize, Deserialize)]
//! struct BackupKey(Vec<u8>);
//!
//! impl Zeroize for BackupKey {
//!     fn zeroize(&mut self) { self.0.zeroize(); }
//! }
//!
//! // Every impl is a deliberate security decision — audit all usages.
//! impl SerializableSecret for BackupKey {}
//!
//! // `Dynamic`, not `Fixed`: the payload is a `Vec`, so its capacity can change, and
//! // `Fixed::new` now refuses it. This example used to use `Fixed` and was itself an
//! // instance of the weakness `SECURITY.md` documents.
//! let key = Dynamic::new(BackupKey(vec![0u8; 32]));
//! // Serialization exposes the secret — encrypt/authenticate output before storage.
//! // let bytes = serde_json::to_vec(&key).unwrap();
//! let _ = key;
//! ```
//!
//! # Warnings
//!
//! - **Serialization exposes the secret** — treat serialized output as sensitive.
//!   Encrypt, authenticate, and protect transmission/storage.
//! - **Audit every impl** — ensure the inner type correctly implements `Serialize`
//!   (and, independently, `Deserialize` if you need it) and `Zeroize`.
//! - **Prefer ephemeral secrets** — avoid persisting raw secrets when possible.
//!
//! This trait is a **marker only** — it has no methods and adds no runtime behavior.
//! It exists solely to gate `Serialize` on wrapper types.
//!
//! The pattern is fully supported: [`RevealSecret`](crate::RevealSecret) is
//! implemented for **every** inner type, so a secret built this way remains
//! readable after opting into serialization — the opt-in does not cost you
//! the access API.

/// Marker trait that opts a secret type into serialization.
///
/// No methods — its only purpose is to gate the `Serialize` impl on
/// [`Fixed<T>`](crate::Fixed) and [`Dynamic<T>`](crate::Dynamic).
/// Requires the `serde-serialize` feature.
#[cfg(feature = "serde-serialize")]
pub trait SerializableSecret: serde::Serialize {}
