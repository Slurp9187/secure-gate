//! Integration test runner for `secure-gate-compat`'s directory-based suites.
//!
//! Compiles `compat_suite/`, `compat_dual/` and `proptest_suite/` into a single
//! binary. Without this file cargo compiles none of them.
//!
//! Flat test files at `tests/` root (`migration_full`, `finding5_regression`) each
//! run as their own binary — that is intentional, not a gap. `compile_fail_tests.rs`
//! is also kept separate because it uses trybuild.
#![allow(clippy::redundant_clone)]

#[cfg(feature = "secrecy-compat")]
mod common;
#[cfg(feature = "dual-compat-test")]
mod compat_dual;
#[cfg(feature = "secrecy-compat")]
mod compat_suite;

// Proptest is valuable on native runs, but prohibitively slow under Miri's
// interpreter; deterministic suites and the dedicated fuzz/Miri workflow still
// cover UB-oriented paths there.
#[cfg(not(miri))]
mod proptest_suite;
