//! Compatibility layer for migrating from the `secrecy` crate.
//!
//! This crate provides drop-in replacements for `secrecy` v0.8.0 and v0.10.1.
//! It is intended for migration only — new code should use `secure-gate` types directly.
//!
//! `no_std` compatible (requires `alloc` — the shims wrap heap types). Verified in CI
//! by cross-building for a bare-metal target.

// no_std unconditionally: the crate needs alloc (heap-backed shims) but never std.
#![no_std]

pub mod compat;

pub use compat::*;
