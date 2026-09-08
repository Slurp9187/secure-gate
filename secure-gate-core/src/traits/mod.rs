//! Traits for polymorphic secret handling.
//!
//! > **Note:** All traits in this module are re-exported at the crate root
//! > (`secure_gate::RevealSecret`, not `secure_gate::traits::RevealSecret`).
//! > You should never need to import from `secure_gate::traits::*` directly.
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
//! | [`RevealSecret`]       | Read-only scoped / direct access             | Always available         | Preferred: `with_secret` (scoped); escape hatch: `expose_secret`      |
//! | [`SecretLen`]          | Length metadata (`len`, `byte_len`, …)       | Always available         | Only for `[T; N]`, `String`, `Vec<T>`; does not expose contents, but length can itself be sensitive — see trait docs |
//! | [`RevealSecretMut`]    | Mutable scoped / direct access               | Always available         | Same preference: `with_secret_mut` over `expose_secret_mut`           |
//! | [`SentinelValue`]      | Inert placeholder left by `into_inner`       | Always available         | Implemented for `[T; N]` (any `N`), `String`, `Vec<T>`                |
//! | [`ConstantTimeEq`]     | Deterministic constant-time equality         | `ct-eq`                  | Timing-attack resistant byte comparison                               |
//! | [`CloneableSecret`]    | Opt-in marker for safe cloning               | `cloneable`              | Requires explicit impl on inner type; zeroize preserved. See [`SECURITY.md`](https://github.com/Slurp9187/secure-gate/blob/release/0.8/secure-gate-core/SECURITY.md) for opt-in risk details. |
//! | [`SerializableSecret`] | Opt-in marker for Serde serialization        | `serde-serialize`        | Serialization exposes secret — use with extreme caution. See [`SECURITY.md`](https://github.com/Slurp9187/secure-gate/blob/release/0.8/secure-gate-core/SECURITY.md) for opt-in risk details. |
//! | [`EncodableBytes`]     | Gates the encoder blanket impls              | Any `encoding-*`         | Load-bearing: every `To*` blanket is `T: AsRef<[u8]> + EncodableBytes`, which is what keeps `str`, `String` and [`EncodedSecret`] out |
//! | [`SecureEncoding`]     | Vestigial marker for byte-shaped types       | Any `encoding-*`         | Auto-implemented for `T: AsRef<[u8]>`. Nothing in the crate bounds on it; the `To*` traits are gated by [`EncodableBytes`] |
//! | [`SecureDecoding`]     | Vestigial marker for string-shaped types     | Any `encoding-*`         | Auto-implemented for `T: AsRef<str>`. Nothing in the crate bounds on it; the `From*Str` blankets are plain `AsRef<str>` |
//!
//! # Security Guarantees
//!
//! - **No implicit access while held** — Reaching a secret inside `Fixed`/`Dynamic`
//!   requires an explicit trait method. `into_inner` ends that protection and hands
//!   back the plain value; the encoders return [`EncodedSecret`], which derefs by design
//! - **Scoped preference** — `with_secret` / `with_secret_mut` limit borrow lifetime
//! - **Zero-cost** — All methods use `#[inline(always)]` where possible
//! - **Timing safety** — `ConstantTimeEq` provides constant-time equality
//! - **Opt-in risk** — Cloning and serialization require deliberate marker impls
//! - **Read-only output** — [`EncodedSecret`] exposes its buffer only through `Deref`
//!   and its two named consumers; there is no mutable access to encoded output
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

pub mod revealed_secrets;

#[cfg(feature = "alloc")]
pub use revealed_secrets::EncodedSecret;

pub mod reveal_secret;
pub use reveal_secret::{RevealSecret, SecretLen};

pub mod reveal_secret_mut;
pub use reveal_secret_mut::RevealSecretMut;

pub mod sentinel_value;
pub use sentinel_value::SentinelValue;

#[cfg(feature = "ct-eq")]
pub mod constant_time_eq;
#[cfg(feature = "ct-eq")]
pub use constant_time_eq::ConstantTimeEq;

pub mod decoding;
pub mod encoding;

// Re-export per-format decoding traits (feature-gated; blanket impls return Vec<u8> — alloc required)
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
pub use decoding::FromBase32Str;

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub use decoding::FromBase64UrlStr;

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use decoding::FromBech32Str;

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use decoding::FromBech32mStr;

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
pub use decoding::FromHexStr;

// Re-export per-format encoding traits (feature-gated)
// Note: blanket impls of ToBase32, ToBase64Url, ToBech32, ToBech32m require alloc (String output).
// Each trait is exported only with its own encoding feature *and* alloc, because every
// encoder returns EncodedSecret and that type requires alloc.
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
pub use encoding::ToBase32;

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub use encoding::ToBase64Url;

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use encoding::ToBech32;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
pub use encoding::EncodableBytes;

#[cfg(feature = "encoding-bech32")]
pub use encoding::{Bech32Sized, Bech32Standard};

#[cfg(feature = "encoding-bech32")]
pub use encoding::{Bech32mSized, Bech32mStandard};

#[cfg(feature = "encoding-bech32")]
pub use encoding::{bech32_code_length, BECH32_CODE_LENGTH};

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use encoding::ToBech32m;

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
pub use encoding::ToHex;

/// Marker trait for types that support secure encoding operations.
///
/// Automatically implemented for any type that implements `AsRef<[u8]>`,
/// such as `&[u8]`, `Vec<u8>`, `[u8; N]`, etc.
///
/// It does **not** gate the encoding traits. Every `To*` blanket is bounded on
/// `AsRef<[u8]> + `[`EncodableBytes`], and this marker is
/// implemented for `str` and `String` too — precisely the types `EncodableBytes`
/// exists to reject. Nothing in the crate bounds on this trait; the 0.9 line removed
/// it. It is retained here for backwards compatibility.
///
/// Since this is a marker trait (no methods), it exists only to allow trait
/// bounds and extension methods to be available where appropriate.
///
/// Requires at least one `encoding-*` feature to be enabled.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
pub trait SecureEncoding {}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
impl<T: AsRef<[u8]> + ?Sized> SecureEncoding for T {}

/// Marker trait for types that support secure decoding operations.
///
/// Automatically implemented for any type that implements `AsRef<str>`,
/// such as `&str`, `String`, etc.
///
/// It does **not** gate the decoding traits: each `From*Str` blanket is bounded on
/// plain `AsRef<str>` and does not mention this marker. Nothing in the crate bounds
/// on it; the 0.9 line removed it. Retained here for backwards compatibility.
///
/// Like `SecureEncoding`, this is a marker trait with no methods — it exists
/// to allow trait bounds and extension methods where relevant.
///
/// Requires at least one `encoding-*` feature to be enabled.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
pub trait SecureDecoding {}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
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
