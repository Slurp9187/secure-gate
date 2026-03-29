//! Suite integration runner for secure-gate v0.8.0.
//!
//! Compiles the directory-based test suites into a single binary.
//! Flat test files (`core_tests`, `ct_eq_tests`, `zeroize_tests`, `error_tests`, …)
//! each run as their own binary — that is intentional, not a gap.
//!
//! Separate binaries are also kept for:
//! - `heap_zeroize.rs`       (uses #[global_allocator])
//! - `compile_fail_tests.rs` (uses trybuild)
#![allow(clippy::redundant_clone)]

mod common;

mod encoding_suite;
mod macros_suite;
mod revealed_secrets_suite;
mod serde_suite;
// Proptest is valuable on native runs, but prohibitively slow under Miri's
// interpreter; deterministic suites and the dedicated fuzz/Miri workflow still
// cover UB-oriented paths there.
#[cfg(not(miri))]
mod proptest_suite;
