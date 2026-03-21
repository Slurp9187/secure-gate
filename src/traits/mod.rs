//! Traits for polymorphic secret handling.
//!
//! This module defines the core traits that enable generic, zero-cost, and secure
//! operations across different secret wrapper types (`Fixed<T>`, `Dynamic<T>`, etc.).
//! These traits allow writing polymorphic code that preserves strong security invariants:
//! explicit access, controlled mutability, timing safety, and opt-in risk features.
//!
//! # Core Traits
//!
//! | Trait                  | Purpose                                      | Requires Feature         | Notes                                                                 |
//! |------------------------|----------------------------------------------|--------------------------|-----------------------------------------------------------------------|
//! | [`ExposeSecret`]       | Read-only scoped / direct access + metadata  | Always available         | Preferred: `with_secret` (scoped); escape hatch: `expose_secret`      |
//! | [`ExposeSecretMut`]    | Mutable scoped / direct access               | Always available         | Same preference: `with_secret_mut` over `expose_secret_mut`           |
//! | [`ConstantTimeEq`]     | Deterministic constant-time equality         | `ct-eq`                  | Timing-attack resistant byte comparison                               |
//! | [`CloneableSecret`]    | Opt-in marker for safe cloning               | `cloneable`              | Requires explicit impl on inner type; zeroize preserved. See [`SECURITY.md`](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for opt-in risk details. |
//! | [`SerializableSecret`] | Opt-in marker for Serde serialization        | `serde-serialize`        | Serialization exposes secret — use with extreme caution. See [`SECURITY.md`](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for opt-in risk details. |
//! | [`SecureEncoding`]     | Marker + blanket impl for encoding traits    | Any `encoding-*`         | Enables `ToHex`, `ToBase64Url`, `ToBech32`, `ToBech32m`               |
//! | [`SecureDecoding`]     | Marker + blanket impl for decoding traits    | Any `encoding-*`         | Enables `FromHexStr`, `FromBase64UrlStr`, `FromBech32Str`, etc.       |
//!
//! # Security Guarantees
//!
//! - **No implicit access** — All secret data access requires explicit trait methods
//! - **Scoped preference** — `with_secret` / `with_secret_mut` limit borrow lifetime
//! - **Zero-cost** — All methods use `#[inline(always)]` where possible
//! - **Timing safety** — `ConstantTimeEq` provides constant-time equality
//! - **Opt-in risk** — Cloning and serialization require deliberate marker impls
//! - **Read-only enforcement** — Encoding wrappers and random types only expose immutable access
//!
//! # Feature Gates
//!
//! Some traits are only available when their corresponding Cargo features are enabled:
//!
//! - `ct-eq`          → [`ConstantTimeEq`]
//! - `cloneable`      → [`CloneableSecret`]
//! - `serde-serialize`→ [`SerializableSecret`]
//! - `encoding-*`     → [`SecureEncoding`], [`SecureDecoding`], and per-format traits
//!
//! The encoding traits (`ToHex`, `FromHexStr`, etc.) are re-exported from submodules for convenience.
//!
//! See individual trait docs for detailed usage and examples.

pub mod expose_secret;
pub use expose_secret::ExposeSecret;

pub mod expose_secret_mut;
pub use expose_secret_mut::ExposeSecretMut;

#[cfg(feature = "ct-eq")]
pub mod constant_time_eq;
#[cfg(feature = "ct-eq")]
pub use constant_time_eq::ConstantTimeEq;

pub mod decoding;
pub mod encoding;

// Re-export per-format decoding traits (feature-gated)
#[cfg(feature = "encoding-base64")]
pub use decoding::FromBase64UrlStr;

#[cfg(feature = "encoding-bech32")]
pub use decoding::FromBech32Str;

#[cfg(feature = "encoding-bech32m")]
pub use decoding::FromBech32mStr;

#[cfg(feature = "encoding-hex")]
pub use decoding::FromHexStr;

// Re-export per-format encoding traits (feature-gated)
#[cfg(feature = "encoding-base64")]
pub use encoding::ToBase64Url;

#[cfg(feature = "encoding-bech32")]
pub use encoding::ToBech32;

#[cfg(feature = "encoding-bech32m")]
pub use encoding::ToBech32m;

#[cfg(feature = "encoding-hex")]
pub use encoding::ToHex;

/// Marker trait for types that support secure encoding operations.
///
/// Automatically implemented for any type that implements `AsRef<[u8]>`,
/// such as `&[u8]`, `Vec<u8>`, `[u8; N]`, etc. This enables blanket impls
/// of the individual encoding traits (`ToHex`, `ToBase64Url`, `ToBech32`, etc.).
///
/// Since this is a marker trait (no methods), it exists only to allow trait
/// bounds and extension methods to be available where appropriate.
///
/// Requires at least one `encoding-*` feature to be enabled.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
))]
pub trait SecureEncoding {}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
))]
impl<T: AsRef<[u8]> + ?Sized> SecureEncoding for T {}

/// Marker trait for types that support secure decoding operations.
///
/// Automatically implemented for any type that implements `AsRef<str>`,
/// such as `&str`, `String`, etc. This enables blanket impls of the
/// individual decoding traits (`FromHexStr`, `FromBase64UrlStr`, etc.).
///
/// Like `SecureEncoding`, this is a marker trait with no methods — it exists
/// to allow trait bounds and extension methods where relevant.
///
/// Requires at least one `encoding-*` feature to be enabled.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
))]
pub trait SecureDecoding {}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
))]
impl<T: AsRef<str> + ?Sized> SecureDecoding for T {}

#[cfg(feature = "cloneable")]
pub mod cloneable_secret;
#[cfg(feature = "cloneable")]
pub use cloneable_secret::CloneableSecret;

#[cfg(feature = "serde-serialize")]
pub mod serializable_secret;
#[cfg(feature = "serde-serialize")]
pub use serializable_secret::SerializableSecret;
