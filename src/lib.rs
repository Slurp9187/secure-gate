// Allow unsafe_code when encoding or zeroize is enabled (encoding needs it for hex validation)
#![cfg_attr(
    not(any(
        feature = "zeroize",
        any(feature = "encoding-hex", feature = "encoding-base64")
    )),
    forbid(unsafe_code)
)]
// #![doc = include_str!("../README.md")]  // uncomment for doctest runs
//! Zero-cost secure wrappers for secrets — [`Fixed<T>`] for stack, [`Dynamic<T>`] for heap.
//!
//! This crate provides explicit wrappers for sensitive data like [`CloneableArray`], [`CloneableString`], and [`CloneSafe`], ensuring no accidental exposure.
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
pub use traits::{ExposeSecret, ExposeSecretMut};

/// Re-export of SecureRandom (requires `rand` feature).
#[cfg(feature = "rand")]
pub use traits::SecureRandom;

/// Re-export of the [`CloneSafe`] trait.
#[cfg(feature = "zeroize")]
pub use traits::CloneSafe;

/// Re-export of the [`SerializableSecret`] trait.
#[cfg(feature = "serde")]
pub use traits::SerializableSecret;

/// Re-export of the [`ConstantTimeEq`] trait.
#[cfg(feature = "ct-eq")]
pub use traits::ConstantTimeEq;

/// Cloneable secret types (requires the `zeroize` feature).
/// Provides wrappers that can be safely duplicated while maintaining security guarantees.
#[cfg(feature = "zeroize")]
pub mod cloneable;
/// Re-exports of cloneable secret types: [`CloneableArray`], [`CloneableString`], [`CloneableVec`].
#[cfg(feature = "zeroize")]
pub use cloneable::{CloneableArray, CloneableString, CloneableVec};

/// Type alias macros (always available).
/// Convenient macros for creating custom secret wrapper types.
mod macros;

/// Available macros (exported globally for convenience):
/// - `dynamic_alias!`: Create type aliases for heap-allocated secrets (`Dynamic<T>`).
/// - `dynamic_generic_alias!`: Create generic heap-allocated secret aliases.
/// - `fixed_alias!`: Create type aliases for fixed-size secrets (`Fixed<[u8; N]>`).
/// - `fixed_generic_alias!`: Create generic fixed-size secret aliases.
/// - `fixed_alias_random!`: Create type aliases for random-only fixed-size secrets (`FixedRandom<N>`, requires `rand` feature).
/// Cryptographically secure random generation (requires the `rand` feature).
/// Provides RNG-backed secret generation with freshness guarantees.
#[cfg(feature = "rand")]
pub mod random;

/// Encoding utilities for secrets (various encoding features available).
/// Secure encoding/decoding with validation and zeroization.
pub mod encoding;

/// Re-exports for convenient access to feature-gated types.
#[cfg(feature = "rand")]
pub use random::{DynamicRandom, FixedRandom};

/// Re-export of [`HexString`] for convenience when using hex encoding.
#[cfg(feature = "encoding-hex")]
pub use encoding::hex::HexString;

/// Re-export of [`Base64String`] for convenience when using base64 encoding.
#[cfg(feature = "encoding-base64")]
pub use encoding::base64::Base64String;

/// Re-export of [`Bech32String`] for convenience when using bech32 encoding.
#[cfg(feature = "encoding-bech32")]
pub use encoding::bech32::Bech32String;

/// Re-export of [`Bech32EncodingError`] for convenience when using bech32 encoding.
#[cfg(feature = "encoding-bech32")]
pub use error::Bech32EncodingError;

/// Re-export of [`SecureEncoding`] trait for convenient encoding extensions.
/// Re-export of the [`SecureEncoding`] trait.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub use traits::SecureEncoding;

/// Re-export of the [`FromSliceError`] type.
pub use error::FromSliceError;
