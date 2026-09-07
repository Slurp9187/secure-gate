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
//! | [`CloneableSecret`]    | Opt-in marker for safe cloning               | `cloneable`              | Requires explicit impl on inner type; zeroize preserved. See [`SECURITY.md`](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for opt-in risk details. |
//! | [`SerializableSecret`] | Opt-in marker for Serde serialization        | `serde-serialize`        | Serialization exposes secret — use with extreme caution. See [`SECURITY.md`](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for opt-in risk details. |
//!
//! # Security Guarantees
//!
//! - **No implicit access while held** — Reaching a secret inside `Fixed`/`Dynamic`
//!   requires an explicit trait method. The output wrappers returned by extraction
//!   ([`InnerSecret`], [`EncodedSecret`]) deref by design
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
//! - `encoding-*`     → per-format encoding / decoding traits (`ToHex`, `FromHexStr`, …)
//!
//! The encoding traits (`ToHex`, `FromHexStr`, etc.) are re-exported from submodules for convenience.
//!
//! See individual trait docs for detailed usage and examples.

pub mod revealed_secrets;
pub use revealed_secrets::InnerSecret;

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
// The traits themselves are exported unconditionally so inherent methods on Fixed/Dynamic
// can call them; the blanket impls gate the alloc dependency.
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
pub use encoding::ToBase32;

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub use encoding::ToBase64Url;

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use encoding::ToBech32;

#[cfg(feature = "encoding-bech32")]
pub use encoding::{Bech32Sized, Bech32Standard};

#[cfg(feature = "encoding-bech32")]
pub use encoding::{Bech32mSized, Bech32mStandard};

#[cfg(feature = "encoding-bech32")]
pub use encoding::{BECH32_CODE_LENGTH, bech32_code_length};

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use encoding::ToBech32m;

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
pub use encoding::ToHex;

#[cfg(feature = "cloneable")]
pub mod cloneable_secret;
#[cfg(feature = "cloneable")]
pub use cloneable_secret::CloneableSecret;

#[cfg(feature = "serde-serialize")]
pub mod serializable_secret;
#[cfg(feature = "serde-serialize")]
pub use serializable_secret::SerializableSecret;
