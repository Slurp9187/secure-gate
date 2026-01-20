// Allow unsafe_code when encoding or zeroize is enabled (encoding needs it for hex validation)
#![cfg_attr(
    not(any(
        feature = "zeroize",
        any(feature = "encoding-hex", feature = "encoding-base64")
    )),
    forbid(unsafe_code)
)]
// #![doc = include_str!("../README.md")] // uncomment for doctest runs
// #![doc = include_str!("../EXAMPLES.md")] // uncomment for doctest runs
//! Zero-cost secure wrappers for secrets — [`Fixed<T>`] for stack, [`Dynamic<T>`] for heap.
//!
//! This crate provides explicit wrappers for sensitive data like [`CloneableArray`], [`CloneableString`], and [`CloneableType`], ensuring no accidental exposure.
//! See [README.md](https://github.com/Slurp9187/secure-gate) for usage and examples.

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

/// Re-export of the traits.
pub use traits::{ExposeSecret, ExposeSecretMut, RedactedDebug};

/// Re-export of the [`SecureConstruction`] trait.
#[cfg(any(
    feature = "rand",
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub use traits::SecureConstruction;

/// Re-export of the [`HashEqSecret`] trait.
#[cfg(feature = "hash-eq")]
pub use traits::HashEqSecret;

/// Re-export of the [`ConstantTimeEq`] trait.
#[cfg(feature = "ct-eq")]
pub use traits::ConstantTimeEq;

/// Type alias macros (always available).
/// Convenient macros for creating custom secret wrapper types.
mod macros;

/// Available macros (exported globally for convenience):
/// - `dynamic_alias!`: Create type aliases for heap-allocated secrets (`Dynamic<T>`).
/// - `dynamic_generic_alias!`: Create generic heap-allocated secret aliases.
/// - `fixed_alias!`: Create type aliases for fixed-size secrets (`Fixed<[u8; N]>`).
/// - `fixed_generic_alias!`: Create generic fixed-size secret aliases.
/// Encoding utilities for secrets (various encoding features available).
/// Secure encoding/decoding with validation and zeroization.
pub mod encoding;

/// Re-export of [`SecureEncoding`] trait for convenient encoding extensions.
/// Re-export of the [`SecureEncoding`] trait.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub use traits::SecureEncoding;

/// Re-export of [`Bech32EncodingError`] for convenience when using bech32 encoding.
#[cfg(feature = "encoding-bech32")]
pub use error::Bech32EncodingError;
