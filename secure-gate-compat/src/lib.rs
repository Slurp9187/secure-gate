#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Compatibility shims for the `secrecy` crate.
//!
//! Provides drop-in replacements and migration paths from `secrecy` v0.8 and v0.10
//! using the `secure-gate` library. The `secrecy-compat` feature enables the
//! compatibility modules.
//!
//! See the [migration guide](MIGRATING_FROM_SECRECY.md) for details.

pub use secure_gate::*;

#[cfg(feature = "secrecy-compat")]
pub mod compat;
