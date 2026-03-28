//! Integration test runner for `secure-gate` directory-based suites.
//!
//! Compiles those suites into a single binary.
//! Flat test files (`core_tests`, `ct_eq_tests`, `zeroize_tests`, `error_tests`, …)
//! each run as their own binary — that is intentional, not a gap.
//!
//! Separate binaries are also kept for:
//! - `heap_zeroize.rs`       (uses #[global_allocator])
//! - `compile_fail_tests.rs` (uses trybuild)
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
