// secure-gate\src\macros\serializable_types\mod.rs

//! Serializable type macros for secure secret serialization.
//!
//! This module provides macros for creating type aliases that allow opt-in serialization
//! of secrets while maintaining security properties.

mod dynamic;
mod fixed;

// Macros are exported at the crate root via #[macro_export]
