// Forbid unsafe code unconditionally
#![forbid(unsafe_code)]

//! secure-gate 0.8.0-alpha.1 — Secure secret wrappers with explicit access & automatic zeroization
//!
//! **Alpha release after yanking all prior versions due to a critical zeroize-on-drop bug.**
//!
//! Secrets are **automatically zeroized on drop** (inner type must implement [`Zeroize`](zeroize::Zeroize)).
//! Explicit access only via [`ExposeSecret`]/[`ExposeSecretMut`] — no `Deref`, no accidental leaks.
//! `Debug` always prints `[REDACTED]`.
//!
//! - [`Fixed<T>`] — stack-allocated, compile-time-sized secrets (keys, nonces, tokens)
//! - [`Dynamic<T>`] — heap-allocated, variable-length secrets (passwords, API keys, ciphertexts)
//!
//! # Feature flags
//!
//! - `alloc` *(default)*: Heap-allocated [`Dynamic<T>`] + full zeroization of spare capacity
//! - `no-alloc`: Disables heap (only [`Fixed<T>`] available — pure stack / `no_std`)
//! - `ct-eq`: [`ConstantTimeEq`] constant-time equality
//! - `ct-eq-hash`: [`ConstantTimeEqExt`] BLAKE3-based probabilistic equality
//! - `rand`: Secure random generation via `OsRng`
//! - `cloneable`: [`CloneableSecret`] opt-in cloning
//! - `serde-serialize` / `serde-deserialize`: Serde support
//! - `encoding-hex` / `encoding-base64` / `encoding-bech32` / `encoding-bech32m`: Per-format encoding
//! - `full`: All features
//!
//! # no_std
//!
//! `no_std` compatible. [`Fixed<T>`] works without `alloc`. Enable `alloc` (default) for
//! [`Dynamic<T>`]. Use `no-alloc` for pure stack / embedded builds.
//!
//! Note: Enabling both `alloc` and `no-alloc` is a compile error unless the `full` feature is also active
//! (the `full`/`--all-features` case is allowed so that `cargo doc --all-features` continues to work).
//!
//! See [README](https://github.com/Slurp9187/secure-gate) and
//! [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for full details.

#[cfg(all(feature = "alloc", feature = "no-alloc", not(feature = "full")))]
compile_error!(
    "Features `alloc` and `no-alloc` are mutually exclusive. \
     Enable only one. Use `no-alloc` alone for embedded/no-heap builds."
);

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

#[cfg(feature = "ct-eq-hash")]
/// Probabilistic constant-time equality using BLAKE3 hash.
///
/// Provides `ct_eq_hash()` method. Requires `ct-eq-hash` feature.
pub use traits::ConstantTimeEqExt;

/// Explicit immutable access to secret contents.
///
/// Provides `expose_secret()` and `with_secret()` methods.
pub use traits::ExposeSecret;

/// Explicit mutable access to secret contents.
///
/// Provides `expose_secret_mut()` and `with_secret_mut()` methods.
pub use traits::ExposeSecretMut;

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
    feature = "encoding-bech32m"
))]
pub use traits::SecureDecoding;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m"
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
