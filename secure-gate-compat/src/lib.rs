
//! Compatibility layer for migrating from the `secrecy` crate.
//!
//! This crate provides drop-in replacements for `secrecy` v0.8.0 and v0.10.1.
//! It is intended for migration only — new code should use `secure-gate` types directly.

pub mod v08;
pub mod v10;

// Re-export shared traits from the core crate
pub use secure_gate::{
    CloneableSecret,
    ExposeSecret,
    ExposeSecretMut,
    RevealSecret,
    RevealSecretMut,
    SerializableSecret,
};

#[doc(inline)]
pub use secure_gate::zeroize;
