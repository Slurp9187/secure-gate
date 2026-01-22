// Forbid unsafe code unconditionally
#![forbid(unsafe_code)]
// #![doc = include_str!("../README.md")] // uncomment for doctest runs
// #![doc = include_str!("../EXAMPLES.md")] // uncomment for doctest runs
//! Zero-cost secure wrappers for secrets — [`Fixed<T>`] for stack, [`Dynamic<T>`] for heap.
//!
//! This crate provides explicit wrappers for sensitive data like \[`CloneableArray`\], \[`CloneableString`\], and \[`CloneableType`\], ensuring no accidental exposure.
//! See README.md for usage and examples.
extern crate alloc;

/// Dynamic secret wrapper types - always available with zero dependencies.
/// These provide fundamental secure storage abstractions for dynamic data.
mod dynamic;

/// Fixed-size secret wrapper types - always available with zero dependencies.
/// These provide fundamental secure storage abstractions for fixed-size data.
mod fixed;

/// Centralized error types - always available.
mod error;

/// Core traits for wrapper polymorphism - always available.
mod traits;

/// Re-export of the [`Dynamic`] type.
pub use dynamic::Dynamic;
/// Re-export of the [`Fixed`] type.
pub use fixed::Fixed;

#[cfg(feature = "cloneable")]
pub use traits::CloneableType;
#[cfg(feature = "serde-serialize")]
pub use traits::SerializableType;
/// Re-export of the traits.
pub use traits::{ExposeSecret, ExposeSecretMut};

/// Re-export of the [`ConstantTimeEq`] trait.
#[cfg(feature = "ct-eq")]
pub use traits::ConstantTimeEq;

/// Re-export of the [`HashEq`] trait.
#[cfg(feature = "hash-eq")]
pub use traits::HashEq;

/// Type alias macros (always available).
/// Convenient macros for creating custom secret wrapper types.
mod macros;

/// Available macros (exported globally for convenience):
/// - `cloneable_fixed_alias!`: Create cloneable type aliases for fixed-size secrets.
/// - `cloneable_dynamic_alias!`: Create cloneable type aliases for dynamic secrets.
/// - `exportable_fixed_alias!`: Create exportable type aliases for fixed-size secrets.
/// - `exportable_dynamic_alias!`: Create exportable type aliases for dynamic secrets.
/// - `dynamic_alias!`: Create type aliases for heap-allocated secrets (`Dynamic<T>`).
/// - `dynamic_generic_alias!`: Create generic heap-allocated secret aliases.
/// - `fixed_alias!`: Create type aliases for fixed-size secrets (`Fixed<[u8; N]>`).
/// - `fixed_generic_alias!`: Create generic fixed-size secret aliases.
///   Re-export of [`SecureEncoding`] trait for convenient encoding extensions.
///   Re-export of the [`SecureEncoding`] trait.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub use traits::SecureEncoding;

/// Re-export of [`Bech32Error`] for convenience when using bech32 encoding/decoding.
#[cfg(feature = "encoding-bech32")]
pub use error::Bech32Error;

/// Re-export of [`Base64Error`] for convenience when using base64 decoding.
#[cfg(feature = "encoding-base64")]
pub use error::Base64Error;

/// Re-export of [`HexError`] for convenience when using hex decoding.
#[cfg(feature = "encoding-hex")]
pub use error::HexError;

/// Re-export of [`DecodingError`] for convenience in decoding operations.
pub use error::DecodingError;
