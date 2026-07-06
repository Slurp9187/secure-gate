#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Compatibility shims for the `secrecy` crate.
//!
//! Provides drop-in replacements and migration paths from `secrecy` v0.8 and v0.10
//! using the `secure-gate` library. The `secrecy-compat` feature enables the
//! compatibility modules.
//!
//! `no_std` compatible (requires `alloc` — the shims wrap heap types). Verified in CI
//! by cross-building for a bare-metal target.
//!
//! See the [migration guide](MIGRATING_FROM_SECRECY.md) for details.

// no_std unconditionally: the crate needs alloc (heap-backed shims) but never std.
#![no_std]

pub use secure_gate::*;

#[cfg(feature = "secrecy-compat")]
pub mod compat;
