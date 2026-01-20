//! Public type alias macros for creating custom secret wrapper types.
//!
//! This module provides macros for generating type aliases to `Dynamic` and `Fixed` types,
//! allowing users to create domain-specific secret types without boilerplate.
//!
//! The macros in this module help create named aliases like:
//! - `dynamic_alias!(MySecretVec, Vec<u8>)` → type alias for `Dynamic<Vec<u8>>`
//! - `fixed_alias!(MySecretKey, 32)` → type alias for `Fixed<[u8; 32]>`
//!
//! These aliases maintain all security properties of the underlying types while providing
//! better ergonomics and type safety in application code.

/// Macros for creating Dynamic type aliases (heap-allocated secrets).
mod dynamic;

/// Macros for creating Fixed type aliases (stack-allocated secrets).
mod fixed;
