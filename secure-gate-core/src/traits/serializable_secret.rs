//! Opt-in marker trait for safe, explicit Serde serialization of secrets.
//!
//! This trait acts as a deliberate security gate: it enables `Serialize` (and
//! optionally `Deserialize`) implementations on secret wrapper types (`Fixed<T>`,
//! `Dynamic<T>`, aliases) **only** when the inner type explicitly opts in.
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
//! - **Zeroization preserved** — Serialization does **not** bypass `ZeroizeOnDrop`;
//!   all copies zeroize on drop.
//! - **No deserialization by default** — `Deserialize` is **not** automatically
//!   enabled; use `serde-deserialize` feature + manual impl if needed.
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
//! # Example
//!
//! ```rust
//! use secure_gate::{SerializableSecret, Fixed};
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
//! let key = Fixed::new(BackupKey(vec![0u8; 32]));
//! // Serialization exposes the secret — encrypt/authenticate output before storage.
//! // let bytes = bincode::serialize(&key).unwrap();
//! let _ = key;
//! ```
//!
//! # Warnings
//!
//! - **Serialization exposes the secret** — treat serialized output as sensitive.
//!   Encrypt, authenticate, and protect transmission/storage.
//! - **Audit every impl** — ensure the inner type correctly implements `Serialize`
//!   (and `Deserialize` if needed) and `Zeroize`.
//! - **Prefer ephemeral secrets** — avoid persisting raw secrets when possible.
//!
//! This trait is a **marker only** — it has no methods and adds no runtime behavior.
//! It exists solely to gate `Serialize` (and optionally `Deserialize`) on wrapper types.
#[cfg(feature = "serde-serialize")]
/// Marker trait: inner types that opt in to serializing secret wrappers (requires `serde-serialize`).
pub trait SerializableSecret: serde::Serialize {}
