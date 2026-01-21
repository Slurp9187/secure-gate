/// Public type alias macros for creating custom secret wrapper types.
///
/// This module provides macros for generating type aliases and newtype wrappers to `Dynamic` and `Fixed` types,
/// allowing users to create domain-specific secret types with cloning or serialization capabilities without boilerplate.
///
/// The macros in this module help create named aliases like:
/// - `dynamic_alias!(MySecretVec, Vec<u8>)` → type alias for `Dynamic<Vec<u8>>`
/// - `fixed_alias!(MySecretKey, 32)` → type alias for `Fixed<[u8; 32]>`
/// - `cloneable_dynamic_alias!(MySecretVec, Vec<u8>)` → newtype for `Dynamic<Vec<u8>>` with Clone
/// - `serializable_fixed_alias!(MySecretKey, 32)` → newtype for `Fixed<[u8; 32]>` with Serialize/Deserialize
///
/// These aliases maintain all security properties of the underlying types while providing
/// better ergonomics and type safety in application code.

/// Macros for creating Dynamic type aliases (heap-allocated secrets).
mod dynamic;

/// Macros for creating Fixed type aliases (stack-allocated secrets).
mod fixed;

/// Macros for creating cloneable newtype wrappers.
mod clonable_types;

/// Macros for creating serializable newtype wrappers.
mod serializable_types;
