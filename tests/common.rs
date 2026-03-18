//! Shared test helpers for the secure-gate test suite.
//!
//! This file provides common assertions used across the suite test modules.
//! It is compiled only as part of the `integration` test binary — flat test
//! files (`core_tests.rs`, `zeroize_tests.rs`, etc.) have their own binaries
//! and do not have access to these helpers.

// Re-export the most-used traits so suite sub-modules can do `use crate::common::*;`
// Suite modules currently import traits directly from secure_gate, so these are
// available but not yet consumed — suppress the false-positive lint.
#[allow(unused_imports)]
pub use secure_gate::{ExposeSecret, ExposeSecretMut};

/// Asserts that the `Debug` output is exactly `[REDACTED]` in both normal and
/// alternate (`{:#?}`) format — the canonical security invariant for all secret
/// wrapper types.
pub fn assert_redacted_debug(value: &impl core::fmt::Debug) {
    assert_eq!(format!("{value:?}"), "[REDACTED]");
    assert_eq!(format!("{value:#?}"), "[REDACTED]");
}
