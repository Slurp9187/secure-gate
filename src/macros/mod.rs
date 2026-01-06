//! Convenience macros for creating type aliases to secure secret wrappers.
//!
//! This module provides macros that generate type aliases for common secure secret patterns,
//! making it easier to define custom secret types in your application.
//!
//! - `dynamic_alias!`: For heap-allocated secrets (`Dynamic<T>`)
//! - `dynamic_generic_alias!`: For generic heap-allocated secrets
//! - `fixed_alias!`: For fixed-size secrets (`Fixed<[u8; N]>`)
//! - `fixed_generic_alias!`: For generic fixed-size secrets
//! - `fixed_alias_rng!`: For random-only fixed-size secrets (`FixedRng<N>`)

pub mod dynamic;
pub mod fixed;
