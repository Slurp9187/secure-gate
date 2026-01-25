// uncomment for doctest runs
// #![doc = include_str!("../EXAMPLES.md")]
// #![doc = include_str!("../README.md")]

// Forbid unsafe code unconditionally
#![forbid(unsafe_code)]
//! Zero-cost secure wrappers for secrets — [`Dynamic<T>`] for heap-allocated variable-length data,
//! [`Fixed<T>`] for stack-allocated fixed-size data.
//!
//! This crate provides explicit, guarded wrappers for sensitive values (e.g. keys, tokens, ciphertexts)
//! with controlled exposure via `.expose_secret()` / `.expose_secret_mut()`. No accidental leaks via
//! `Deref`, `AsRef`, or implicit conversions.
//!
//! See [README.md](../README.md) for usage examples, feature overview, and macros for custom aliases.
//!
//! ## Equality Options
//!
//!
//! [`ConstantTimeEq`] (via `ct-eq` feature): Direct byte-by-byte constant-time comparison using `subtle`.
//! Best for small/fixed-size secrets (< ~256–512 bytes) where speed matters most.
//!
//! [`ConstantTimeEqExt`] (via `ct-eq-hash` feature): BLAKE3 hash -> constant-time compare on fixed 32-byte digest.
//! Faster for large/variable secrets (e.g. ML-KEM ciphertexts ~1–1.5 KiB, ML-DSA signatures ~2–4 KiB),
//! with length hiding and optional keyed mode (`rand` for per-process random key).
//!
//! See the ConstantTimeEqExt trait documentation for performance numbers, security properties (probabilistic, timing-safe), and guidance on when to choose each (or hybrid).
#[cfg(feature = "alloc")]
extern crate alloc;

/// Dynamic secret wrapper types - available with `alloc` feature.
/// These provide fundamental secure storage abstractions for dynamic data.
#[cfg(feature = "alloc")]
mod dynamic;

/// Fixed-size secret wrapper types - always available with zero dependencies.
/// These provide fundamental secure storage abstractions for fixed-size data.
mod fixed;

/// Centralized error types - always available.
mod error;

/// Core traits for wrapper polymorphism - always available.
mod traits;

/// Public utility functions.
pub mod utilities;

#[cfg(feature = "alloc")]
/// Re-export of the [`Dynamic`] type.
pub use dynamic::Dynamic;
/// Re-export of the [`Fixed`] type.
pub use fixed::Fixed;

#[cfg(feature = "cloneable")]
pub use traits::CloneableType;
/// Re-export of the traits.
#[cfg(feature = "ct-eq")]
pub use traits::ConstantTimeEq;
#[cfg(feature = "ct-eq-hash")]
pub use traits::ConstantTimeEqExt;
#[cfg(feature = "serde-serialize")]
pub use traits::SerializableType;
pub use traits::{ExposeSecret, ExposeSecretMut};

/// Type alias macros (always available).
/// Convenient macros for creating custom secret wrapper types.
mod macros;
/// Available macros (exported globally for convenience):
/// - `dynamic_alias!`: Create type aliases for heap-allocated secrets (`Dynamic<T>`).
/// - `dynamic_generic_alias!`: Create generic heap-allocated secret aliases.
/// - `fixed_alias!`: Create type aliases for fixed-size secrets (`Fixed<[u8; N]>`).
/// - `fixed_generic_alias!`: Create generic fixed-size secret aliases.
///   Re-exports of encoding and decoding traits for convenient byte encoding/decoding extensions.
#[cfg(feature = "encoding-base64")]
pub use traits::FromBase64UrlStr;
#[cfg(feature = "encoding-bech32")]
pub use traits::FromBech32Str;
#[cfg(feature = "encoding-bech32m")]
pub use traits::FromBech32mStr;
#[cfg(feature = "encoding-hex")]
pub use traits::FromHexStr;

#[cfg(feature = "encoding-base64")]
pub use traits::ToBase64Url;
#[cfg(feature = "encoding-bech32")]
pub use traits::ToBech32;
#[cfg(feature = "encoding-bech32m")]
pub use traits::ToBech32m;
#[cfg(feature = "encoding-hex")]
pub use traits::ToHex;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m"
))]
pub use traits::{SecureDecoding, SecureEncoding};

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

#[cfg(feature = "serde-deserialize")]
pub use utilities::decoding::try_decode_any;
/// Re-export decoding utilities for multi-format auto-decoding.
#[cfg(any(
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
    feature = "encoding-hex",
    feature = "encoding-base64"
))]
pub use utilities::decoding::Format;
