//! Integration test runner for `secure-gate` directory-based suites.
//!
//! Compiles those suites into a single binary.
//! Flat test files (`core_tests`, `ct_eq_tests`, `zeroize_tests`, `error_tests`, …)
//! each run as their own binary — that is intentional, not a gap.
//!
//! Separate binaries are also kept for:
//! - `heap_zeroize.rs`       (uses #[global_allocator])
//! - `compile_fail_tests.rs` (uses trybuild)

mod common;
mod encoding_suite;
mod serde_suite;
mod macros_suite;
// The compat_suite gate lives entirely inside compat_suite/mod.rs
// (#![cfg(feature = "secrecy-compat")]). No cfg is needed here.
mod compat_suite;
// Proptest is valuable on native runs, but prohibitively slow under Miri's
// interpreter; deterministic suites and the dedicated fuzz/Miri workflow still
// cover UB-oriented paths there.
#[cfg(not(miri))]
mod proptest_suite;
