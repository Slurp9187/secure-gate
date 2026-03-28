//! Compatibility layer for migrating from the `secrecy` crate.
//!
//! This crate provides drop-in replacements for `secrecy` v0.8.0 and v0.10.1.
//! It is intended for migration only — new code should use `secure-gate` types directly.

pub mod compat;

pub use compat::*;
