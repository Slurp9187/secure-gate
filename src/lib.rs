// ==========================================================================
// src/lib.rs
// ==========================================================================

// Allow unsafe_code when encoding or zeroize is enabled (encoding needs it for hex validation)
#![cfg_attr(
    not(any(
        feature = "zeroize",
        any(feature = "encoding-hex", feature = "encoding-base64")
    )),
    forbid(unsafe_code)
)]
#![doc = include_str!("../README.md")]

extern crate alloc;

/// Core secret wrapper types - always available with zero dependencies.
/// These provide the fundamental secure storage abstractions.
mod dynamic;
mod fixed;

pub use dynamic::Dynamic;
pub use fixed::Fixed;

/// Cloneable secret types - requires "zeroize" feature.
/// Provides wrappers that can be safely duplicated while maintaining security guarantees.
#[cfg(feature = "zeroize")]
pub use cloneable::CloneableSecretMarker;
#[cfg(feature = "zeroize")]
pub mod cloneable;
#[cfg(feature = "zeroize")]
pub use cloneable::{CloneableArray, CloneableString, CloneableVec};

/// Type alias macros - always available.
/// Convenient macros for creating custom secret wrapper types.
mod macros;

/// Cryptographically secure random generation - requires "rand" feature.
/// Provides RNG-backed secret generation with freshness guarantees.
#[cfg(feature = "rand")]
pub mod random;

/// Constant-time equality comparison - requires "ct-eq" feature.
/// Prevents timing attacks when comparing sensitive data.
/// Provides the ConstantTimeEq trait for secure comparisons.
#[cfg(feature = "ct-eq")]
pub mod ct_eq;

/// Encoding utilities for secrets - various encoding features available.
/// Secure encoding/decoding with validation and zeroization.
pub mod encoding;

/// Re-exports for convenient access to feature-gated types.
#[cfg(feature = "rand")]
pub use random::{DynamicRandom, FixedRandom};

#[cfg(feature = "encoding-hex")]
pub use encoding::hex::HexString;

#[cfg(feature = "encoding-base64")]
pub use encoding::base64::Base64String;

#[cfg(feature = "encoding-bech32")]
pub use encoding::bech32::Bech32String;

#[cfg(any(feature = "encoding-hex", feature = "encoding-base64"))]
pub use crate::encoding::extensions::SecureEncodingExt;

pub use fixed::FromSliceError;
