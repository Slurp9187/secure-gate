// #![doc = include_str!("../README.md")] //uncomment for doctest runs

// Forbid unsafe code unconditionally
#![forbid(unsafe_code)]

//! secure-gate — Secure secret wrappers with explicit access & automatic zeroization
//!
//! Secrets are **automatically zeroized on drop** (the inner type must implement [`Zeroize`](zeroize::Zeroize)).
//! Explicit access only via [`RevealSecret`]/[`RevealSecretMut`] — no `Deref`, no accidental leaks.
//! `Debug` always prints `[REDACTED]`.
//!
//! - [`Fixed<T>`] — stack-allocated, compile-time-sized secrets (keys, nonces, tokens)
//! - [`Dynamic<T>`] — heap-allocated, variable-length secrets (passwords, API keys, ciphertexts)
//!
//! # Feature flags
//!
//! - `alloc` *(default)*: Heap-allocated [`Dynamic<T>`] + full zeroization of spare capacity
//! - `std`: Full `std` support (implies `alloc`)
//! - `ct-eq`: [`ConstantTimeEq`] constant-time equality (`subtle`)
//! - `rand`: `from_random()` via `OsRng`, `from_rng()` for custom `TryCryptoRng` + `TryRngCore`; `no_std` compatible for `Fixed<T>` (no heap required)
//! - `cloneable`: [`CloneableSecret`] opt-in cloning
//! - `serde-serialize` / `serde-deserialize`: Serde support
//! - `encoding-hex` / `encoding-base64` / `encoding-bech32` / `encoding-bech32m`: Per-format encoding
//! - `full`: All features
//!
//! # no_std
//!
//! `no_std` compatible. [`Fixed<T>`] works without `alloc`. Enable `alloc` (default) for
//! [`Dynamic<T>`]. For pure stack / embedded builds, use `default-features = false`.
//!
//! See the [README](https://github.com/Slurp9187/secure-gate/blob/main/README.md) and
//! [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for full details.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod dynamic;

/// Fixed-size secret wrapper types - always available with zero dependencies.
/// These provide fundamental secure storage abstractions for fixed-size data.
mod fixed;

/// Centralized error types - always available.
mod error;

/// Core traits for wrapper polymorphism - always available.
pub mod traits;

#[cfg(feature = "alloc")]
/// Heap-allocated secret wrapper with explicit access and automatic zeroization on drop.
///
/// Requires `alloc` feature. Inner type must implement `Zeroize`.
pub use dynamic::Dynamic;

#[cfg(all(feature = "alloc", feature = "serde-deserialize"))]
/// Default maximum byte length for `Dynamic<Vec<u8>>` / `Dynamic<String>` deserialization (1 MiB).
///
/// The standard `serde::Deserialize` impl for both types rejects payloads exceeding this value.
/// Pass a custom ceiling to [`Dynamic::deserialize_with_limit`] when a different limit is needed.
///
/// **Important:** this limit is enforced *after* the upstream deserializer has fully
/// materialized the payload. It is a **result-length acceptance bound**, not a
/// pre-allocation DoS guard. For untrusted input, enforce size limits at the
/// transport or parser layer upstream.
pub use dynamic::MAX_DESERIALIZE_BYTES;

/// Stack-allocated secret wrapper with explicit access and automatic zeroization on drop.
///
/// Always available. Inner type must implement `Zeroize`.
pub use fixed::Fixed;

#[cfg(feature = "cloneable")]
/// Marker trait for secrets that can be cloned.
///
/// Enables cloning of wrapped secrets. Requires `cloneable` feature.
pub use traits::CloneableSecret;

#[cfg(feature = "ct-eq")]
/// Constant-time equality for secrets.
///
/// Provides `ct_eq()` method using `subtle`. Requires `ct-eq` feature.
pub use traits::ConstantTimeEq;

/// Explicit immutable access to secret contents.
///
/// Provides `expose_secret()` and `with_secret()` methods.
pub use traits::RevealSecret;

/// Explicit mutable access to secret contents.
///
/// Provides `expose_secret_mut()` and `with_secret_mut()` methods.
pub use traits::RevealSecretMut;

#[cfg(feature = "serde-serialize")]
/// Marker trait for secrets that can be serialized with Serde.
///
/// Enables serialization. Requires `serde-serialize` feature.
pub use traits::SerializableSecret;

// Type alias macros (always available)
mod macros;

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
    feature = "encoding-bech32m",
))]
pub use traits::SecureDecoding;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
))]
pub use traits::SecureEncoding;

#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
pub use error::Bech32Error;

#[cfg(feature = "encoding-base64")]
pub use error::Base64Error;

#[cfg(feature = "encoding-hex")]
pub use error::HexError;

pub use error::DecodingError;
pub use error::FromSliceError;
