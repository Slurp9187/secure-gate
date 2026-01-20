/// # Traits for Polymorphic Secret Handling
///
/// This module provides the fundamental traits for working with secrets in a polymorphic,
/// zero-cost way. These traits enable generic code that can operate on different secret
/// wrapper types while maintaining strong security guarantees.
///
/// ## Traits Overview
///
/// - [`ExposeSecret`] - Read-only secret access with metadata
/// - [`ExposeSecretMut`] - Mutable secret access
/// - [`CloneableType`] - Opt-in safe cloning with zeroization (requires zeroize feature)
/// - [`ConstantTimeEq`] - Constant-time equality to prevent timing attacks (requires ct-eq feature)
/// - [`SecureEncoding`] - Extension trait for secure byte encoding to strings (requires encoding features)
/// - [`ExportableType`] - Marker for types allowing secure serialization (requires serde-serialize feature)
///
/// ## Security Guarantees
///
/// - **Read-only enforcement**: Random and encoding wrappers only expose read-only access
/// - **Controlled mutability**: Core wrappers provide full access while others remain read-only
/// - **Zero-cost abstractions**: All traits use `#[inline(always)]` for optimal performance
/// - **Type safety**: Polymorphic operations preserve secret wrapper invariants
///
/// ## Feature Gates
///
/// Some traits require optional Cargo features:
/// - rand: Enables random wrapper implementations
/// - zeroize: Enables [`CloneableType`] for safe cloning
/// - ct-eq: Enables [`ConstantTimeEq`] for constant-time comparisons
/// - encoding (or encoding-hex, encoding-base64, encoding-bech32): Enables [`SecureEncoding`] for byte encoding
/// - serde: Enables [`ExportableType`] for opt-in serialization
// Secret Exposure Traits
pub mod expose_secret;
pub use expose_secret::ExposeSecret;

pub mod expose_secret_mut;
pub use expose_secret_mut::ExposeSecretMut;

pub mod constant_time_eq;
#[cfg(feature = "ct-eq")]
pub use constant_time_eq::ConstantTimeEq;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub mod secure_encoding;
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub use secure_encoding::SecureEncoding;

#[cfg(any(
    feature = "rand",
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub use secure_construction::SecureConstruction;

#[cfg(feature = "hash-eq")]
pub use hash_eq::HashEqSecret;

#[allow(unused_imports)]
pub use cloneable_type::CloneableType;

#[allow(unused_imports)]
pub use exportable_type::ExportableType;

pub mod secure_construction;

#[cfg(feature = "hash-eq")]
pub mod hash_eq;

pub mod cloneable_type;

pub mod exportable_type;
