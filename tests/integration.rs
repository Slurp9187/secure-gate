//! Suite integration runner for secure-gate v0.8.0.
//!
//! Compiles the directory-based test suites into a single binary.
//! Flat test files (core_tests, zeroize_tests, error_tests, no_alloc_tests)
//! each run as their own binary — that is intentional, not a gap.
//!
//! Separate binaries are also kept for:
//! - `heap_zeroize.rs`       (uses #[global_allocator])
//! - `compile_fail_tests.rs` (uses trybuild)

mod common;

#[cfg(feature = "ct-eq")]
mod ct_eq_suite;
mod encoding_suite;
mod serde_suite;
mod macros_suite;
mod proptest_suite;
