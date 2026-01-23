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

/// Public type-alias macros.
/// Dynamic and fixed aliases.
mod dynamic_alias;
mod dynamic_generic_alias;
mod fixed_alias;
mod fixed_generic_alias;
