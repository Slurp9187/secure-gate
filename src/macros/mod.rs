//! Convenience macros for creating type aliases to secure secret wrappers.
//!
//! This module provides macros that generate type aliases for common secure secret patterns,
//! making it easier to define custom secret types in your application.
//!
//! - `dynamic_alias!`: For heap-allocated secrets (`Dynamic<T>`)
//! - `dynamic_generic_alias!`: For generic heap-allocated secrets
//! - `fixed_alias!`: For fixed-size secrets (`Fixed<[u8; N]>`)
//! - `fixed_generic_alias!`: For generic fixed-size secrets
//! - `fixed_alias_random!`: For random-only fixed-size secrets (`FixedRandom<N>`)

/// Dynamic alias macros.
mod dynamic;
/// Fixed alias macros.
mod fixed;

mod impl_ct_eq;
/// Internal macros for secure-gate types.
mod impl_redacted_debug;
mod impl_serde_deserialize;
mod impl_zeroize_integration;
