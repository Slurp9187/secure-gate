// #![doc = include_str!("../README.md")] //uncomment for doctest runs

// Forbid unsafe code unconditionally
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Secure wrappers for secrets with **explicit access** and **mandatory zeroization** — a
//! `no_std`-compatible, zero-overhead library with audit-friendly access patterns.
//!
//! Secrets are **automatically zeroized on drop** (the inner type must implement
//! [`Zeroize`](zeroize::Zeroize)). No `Deref`, no accidental leaks — callers access
//! the inner secret only via [`RevealSecret`] / [`RevealSecretMut`]. `Debug` always
//! prints `[REDACTED]`. All access follows a **3-tier model**: scoped closures (preferred),
//! direct references (escape hatch), and owned extraction (consumption).
//!
//! # Which type should I use?
//!
//! | Type | Allocation | Use case | Feature |
//! |------|-----------|----------|---------|
//! | [`Fixed<T>`] | Stack | Keys, nonces, tokens — compile-time-known size | Always available |
//! | [`Dynamic<T>`] | Heap | Passwords, API keys, ciphertexts — variable length | `alloc` (default) |
//!
//! Both types share the same [`RevealSecret`] / [`RevealSecretMut`] access API.
//!
//! # Quick start
//!
//! ```rust
//! use secure_gate::{Fixed, RevealSecret};
//!
//! // Wrap a 32-byte key
//! let key = Fixed::new([0x42u8; 32]);
//!
//! // Tier 1 — scoped access (preferred): secret ref cannot escape the closure
//! let first = key.with_secret(|bytes| bytes[0]);
//! assert_eq!(first, 0x42);
//!
//! // Tier 2 — direct reference (escape hatch for FFI / third-party APIs)
//! assert_eq!(key.expose_secret().len(), 32);
//!
//! // Debug is always redacted
//! assert_eq!(format!("{:?}", key), "[REDACTED]");
//! // key is zeroized when dropped
//! ```
//!
//! ```rust
//! # #[cfg(feature = "alloc")]
//! # {
//! use secure_gate::{Dynamic, RevealSecret};
//!
//! let password: Dynamic<String> = Dynamic::new(String::from("hunter2"));
//! let len = password.with_secret(|s: &String| s.len());
//! assert_eq!(len, 7);
//! # }
//! ```
//!
//! ```rust
//! use secure_gate::{fixed_alias, RevealSecret};
//!
//! fixed_alias!(pub Aes256Key, 32);
//!
//! let key: Aes256Key = [0xABu8; 32].into();
//! key.with_secret(|b| assert_eq!(b.len(), 32));
//! ```
//!
//! # Module structure
//!
//! ```text
//! secure_gate (lib.rs)
//! ├── Fixed<T>              ← always available, stack-allocated
//! ├── Dynamic<T>            ← requires `alloc`, heap-allocated
//! ├── traits/
//! │   ├── RevealSecret      ← immutable access (always available)
//! │   ├── RevealSecretMut   ← mutable access (always available)
//! │   ├── revealed_secrets/
//! │   │   ├── InnerSecret<T>    ← owned extraction wrapper
//! │   │   └── EncodedSecret     ← zeroizing encoded string wrapper (alloc)
//! │   ├── ConstantTimeEq    ← ct-eq feature
//! │   ├── CloneableSecret   ← cloneable feature
//! │   ├── SerializableSecret← serde-serialize feature
//! │   ├── encoding/         ← ToHex, ToBase64Url, ToBech32, ToBech32m
//! │   └── decoding/         ← FromHexStr, FromBase64UrlStr, FromBech32Str, FromBech32mStr
//! ├── macros/               ← fixed_alias!, dynamic_alias!, etc.
//! └── error                 ← FromSliceError, HexError, Base64Error, Bech32Error, DecodingError
//! ```
//!
//! All public items are re-exported at the crate root. Use `secure_gate::Fixed`,
//! not `secure_gate::fixed::Fixed`.
//!
//! # Import paths
//!
//! ```rust
//! // ✅ Correct — always import from the crate root
//! use secure_gate::{Fixed, RevealSecret};
//!
//! // ❌ Wrong — these internal paths compile but are not the public API
//! // use secure_gate::traits::reveal_secret::RevealSecret;
//! // use secure_gate::traits::encoding::hex::ToHex;
//! ```
//!
//! # Method resolution: wrapper methods vs trait methods
//!
//! Encoding methods exist at **two levels** — both produce identical results:
//!
//! | Call style | Example | Appears in audit sweep? |
//! |-----------|---------|------------------------|
//! | **Wrapper inherent** (ergonomic) | `key.to_hex()` | No — grep for `to_hex` directly |
//! | **Trait via scoped access** (audit-friendly) | `key.with_secret(\|b\| b.to_hex())` | Yes — `with_secret` is grep-able |
//!
//! The wrapper methods ([`Fixed::to_hex`], [`Dynamic::to_hex`](Dynamic::to_hex)) internally call
//! `self.with_secret(|s| s.to_hex())` — they are convenience shorthands, not
//! separate implementations.
//!
//! # Feature flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `alloc` | **yes** | Heap types ([`Dynamic<T>`]), `Vec`/`String` zeroization |
//! | `std` | no | Full `std` support (implies `alloc`) |
//! | | | **Cryptographic** |
//! | `ct-eq` | no | [`ConstantTimeEq`] via `subtle` — timing-safe comparison |
//! | `rand` | no | `from_random()` / `from_rng()` — `no_std` for [`Fixed`] |
//! | | | **Serialization** |
//! | `serde-serialize` | no | Serde `Serialize` (requires [`SerializableSecret`] marker) |
//! | `serde-deserialize` | no | Serde `Deserialize` with 1 MiB default limit |
//! | `serde` | no | Both directions |
//! | | | **Encoding** |
//! | `encoding-hex` | no | [`ToHex`] / [`FromHexStr`] via `base16ct` (constant-time) |
//! | `encoding-base64` | no | [`ToBase64Url`] / [`FromBase64UrlStr`] via `base64ct` (constant-time) |
//! | `encoding-bech32` | no | [`ToBech32`] / [`FromBech32Str`] — BIP-173, extended ~5 KB limit |
//! | `encoding-bech32m` | no | [`ToBech32m`] / [`FromBech32mStr`] — BIP-350, standard 90-byte limit |
//! | `encoding` | no | All encoding features |
//! | | | **Meta** |
//! | `cloneable` | no | [`CloneableSecret`] opt-in cloning |
//! | `full` | no | Everything |
//!
//! # What's available without `alloc`?
//!
//! With `default-features = false`:
//! - [`Fixed<T>`], [`RevealSecret`], [`RevealSecretMut`], [`InnerSecret`]
//! - [`Fixed::try_from_hex`](Fixed::try_from_hex), [`Fixed::try_from_base64url`](Fixed::try_from_base64url),
//!   [`Fixed::try_from_bech32`](Fixed::try_from_bech32), [`Fixed::try_from_bech32m`](Fixed::try_from_bech32m)
//!   (no-alloc stack-based decoding)
//! - [`fixed_alias!`], [`fixed_generic_alias!`]
//! - [`FromSliceError`]
//!
//! **Not** available without `alloc`: [`Dynamic<T>`], [`EncodedSecret`],
//! encoding traits ([`ToHex`], etc.), decoding traits ([`FromHexStr`], etc.),
//! [`dynamic_alias!`], [`dynamic_generic_alias!`], serde support.
//!
//! # `no_std`
//!
//! `no_std` compatible. [`Fixed<T>`] works without `alloc`. Enable `alloc` (default) for
//! [`Dynamic<T>`]. For pure stack / embedded builds, use `default-features = false`.
//! MSRV: **1.85** (Rust edition 2024).
//!
//! # Security
//!
//! This crate has **not** undergone an independent security audit. No unsafe code —
//! enforced with `#![forbid(unsafe_code)]`. Prefer scoped access ([`RevealSecret::with_secret`])
//! over direct references. Prefer zeroizing encoding variants (`to_hex_zeroizing`, etc.)
//! when the encoded form is sensitive. See
//! [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/secure-gate-core/SECURITY.md)
//! for the full threat model.
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

/// Heap-allocated secret wrapper with explicit access and automatic zeroization on drop.
///
/// Variable-length secrets (passwords, API keys, ciphertexts). Inner type must implement
/// `Zeroize`. Secret bytes live on the heap only — never on the stack. Requires `alloc`.
///
/// See [`Fixed<T>`] for the stack-allocated alternative.
///
/// ```rust
/// # #[cfg(feature = "alloc")]
/// # {
/// use secure_gate::{Dynamic, RevealSecret};
///
/// let pw: Dynamic<String> = Dynamic::new(String::from("hunter2"));
/// assert_eq!(pw.with_secret(|s: &String| s.len()), 7);
/// assert_eq!(format!("{:?}", pw), "[REDACTED]");
/// # }
/// ```
#[cfg(feature = "alloc")]
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
/// Fixed-size secrets (keys, nonces, tokens). Inner type must implement `Zeroize`.
/// Always available — works without `alloc`. Prefer [`new_with`](Fixed::new_with) over
/// [`new`](Fixed::new) when minimizing stack residue matters.
///
/// See [`Dynamic<T>`] for the heap-allocated alternative.
///
/// ```rust
/// use secure_gate::{Fixed, RevealSecret};
///
/// let key = Fixed::new([0xABu8; 32]);
/// key.with_secret(|b| assert_eq!(b[0], 0xAB));
/// assert_eq!(format!("{:?}", key), "[REDACTED]");
/// ```
pub use fixed::Fixed;

/// Marker trait that opts a secret type into cloning. No methods — gates the `Clone`
/// impl on [`Fixed`] and [`Dynamic`]. Each clone is independently zeroized on drop,
/// but increases the in-memory exposure surface. Requires `cloneable` feature.
///
/// See also [`SerializableSecret`] (the other opt-in marker trait).
#[cfg(feature = "cloneable")]
pub use traits::CloneableSecret;

/// Constant-time equality for secrets — prevents timing side-channel attacks.
///
/// Provides [`ct_eq()`](ConstantTimeEq::ct_eq) via the `subtle` crate. `==` is
/// **deliberately not implemented** on [`Fixed`] / [`Dynamic`] — always use `ct_eq`.
/// Requires `ct-eq` feature.
///
/// ```rust
/// # #[cfg(feature = "ct-eq")]
/// # {
/// use secure_gate::{Fixed, ConstantTimeEq};
///
/// let a = Fixed::new([1u8; 32]);
/// let b = Fixed::new([1u8; 32]);
/// assert!(a.ct_eq(&b));
/// # }
/// ```
#[cfg(feature = "ct-eq")]
pub use traits::ConstantTimeEq;

/// Explicit immutable access to secret contents (3-tier access model).
///
/// - **Tier 1** (preferred): [`with_secret()`](RevealSecret::with_secret) — scoped closure,
///   borrow cannot escape.
/// - **Tier 2** (escape hatch): [`expose_secret()`](RevealSecret::expose_secret) — direct
///   `&T` reference for FFI / third-party APIs.
/// - **Tier 3** (consumption): [`into_inner()`](RevealSecret::into_inner) — returns
///   [`InnerSecret<T>`] with zeroization transferred to caller.
/// - **Metadata**: [`len()`](RevealSecret::len) / [`is_empty()`](RevealSecret::is_empty) —
///   no secret exposure.
///
/// See [`RevealSecretMut`] for the mutable counterpart.
pub use traits::RevealSecret;

/// Explicit mutable access to secret contents.
///
/// Extends [`RevealSecret`]. Prefer [`with_secret_mut()`](RevealSecretMut::with_secret_mut)
/// (Tier 1) over [`expose_secret_mut()`](RevealSecretMut::expose_secret_mut) (Tier 2).
/// Only [`Fixed`] and [`Dynamic`] implement this — read-only wrappers deliberately do not.
pub use traits::RevealSecretMut;

/// Owned, redacted wrapper returned by [`RevealSecret::into_inner`] (Tier 3 access).
///
/// Wraps [`Zeroizing<T>`](zeroize::Zeroizing) with `Debug` → `[REDACTED]`. Implements
/// `Deref<Target = T>` for ergonomic access (the **only** type in this crate that derefs
/// to the secret — [`Fixed`] and [`Dynamic`] deliberately do not).
///
/// This is **not** a secret wrapper like `Fixed`/`Dynamic` — it is the owned extraction
/// result. Use [`into_zeroizing()`](InnerSecret::into_zeroizing) when an API requires
/// `Zeroizing<T>` directly.
pub use traits::InnerSecret;

/// Owned, redacted wrapper for zeroizing encoded strings.
///
/// Returned by all `*_zeroizing` encoding methods (`to_hex_zeroizing`,
/// `to_base64url_zeroizing`, `try_to_bech32_zeroizing`, etc.). Wraps
/// `Zeroizing<String>` with `Debug` → `[REDACTED]`. Implements `Deref<Target = str>`
/// and `Display`.
///
/// This is **not** a secret wrapper like `Fixed`/`Dynamic` — it is a zeroizing `String`
/// wrapper for encoded output. Use [`into_inner()`](EncodedSecret::into_inner) to extract
/// a plain `String` (ends zeroization) or [`into_zeroizing()`](EncodedSecret::into_zeroizing)
/// to preserve it.
///
/// Requires `alloc` feature.
#[cfg(feature = "alloc")]
pub use traits::EncodedSecret;

/// Marker trait that opts a secret type into Serde serialization. No methods — gates the
/// `Serialize` impl on [`Fixed`] and [`Dynamic`]. Serialization exposes the full secret;
/// audit every impl. Requires `serde-serialize` feature.
///
/// `Deserialize` is gated separately by the `serde-deserialize` feature and does **not**
/// require this marker — it has its own feature-gated impls on the wrapper types directly.
///
/// See also [`CloneableSecret`] (the other opt-in marker trait).
#[cfg(feature = "serde-serialize")]
pub use traits::SerializableSecret;

// Type alias macros (always available)
mod macros;

/// Decodes Base64url strings (`&str`) to `Vec<u8>`. Blanket impl for `AsRef<str>`.
/// Requires `encoding-base64` + `alloc`. See [`ToBase64Url`] for the encoding counterpart.
#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub use traits::FromBase64UrlStr;

/// Decodes Bech32 (BIP-173) strings to `Vec<u8>` with HRP validation.
/// Requires `encoding-bech32` + `alloc`. See [`ToBech32`] for the encoding counterpart.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use traits::FromBech32Str;

/// Decodes Bech32m (BIP-350) strings to `Vec<u8>` with HRP validation.
/// Requires `encoding-bech32m` + `alloc`. See [`ToBech32m`] for the encoding counterpart.
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
pub use traits::FromBech32mStr;

/// Decodes hex strings (`&str`) to `Vec<u8>`. Blanket impl for `AsRef<str>`.
/// Requires `encoding-hex` + `alloc`. See [`ToHex`] for the encoding counterpart.
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
pub use traits::FromHexStr;

/// Encodes byte data as Base64url strings (RFC 4648, URL-safe, no padding).
/// Blanket impl for `AsRef<[u8]>`. Requires `encoding-base64` + `alloc`.
/// See [`FromBase64UrlStr`] for the decoding counterpart.
#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub use traits::ToBase64Url;

/// Encodes byte data as Bech32 (BIP-173) strings with extended ~5 KB payload limit.
/// Blanket impl for `AsRef<[u8]>`. Requires `encoding-bech32` + `alloc`.
/// See [`FromBech32Str`] for the decoding counterpart.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use traits::ToBech32;

/// Encodes byte data as Bech32m (BIP-350) strings with standard 90-byte payload limit.
/// Blanket impl for `AsRef<[u8]>`. Requires `encoding-bech32m` + `alloc`.
/// See [`FromBech32mStr`] for the decoding counterpart.
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
pub use traits::ToBech32m;

/// Encodes byte data as hexadecimal strings (constant-time via `base16ct`).
/// Blanket impl for `AsRef<[u8]>`. Provides `to_hex()`, `to_hex_upper()`, and
/// zeroizing variants. Requires `encoding-hex` + `alloc`.
/// See [`FromHexStr`] for the decoding counterpart.
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
pub use traits::ToHex;

/// Marker trait for types that support secure decoding (`AsRef<str>`). No methods —
/// enables blanket impls of [`FromHexStr`], [`FromBase64UrlStr`], etc.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
))]
pub use traits::SecureDecoding;

/// Marker trait for types that support secure encoding (`AsRef<[u8]>`). No methods —
/// enables blanket impls of [`ToHex`], [`ToBase64Url`], etc.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
))]
pub use traits::SecureEncoding;

/// Errors from Bech32 (BIP-173) and Bech32m (BIP-350) decoding.
/// Debug builds include detailed context; release builds use generic messages.
#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
pub use error::Bech32Error;

/// Errors from Base64url decoding. Debug builds include detailed context;
/// release builds use generic messages.
#[cfg(feature = "encoding-base64")]
pub use error::Base64Error;

/// Errors from hex decoding. Debug builds include detailed context;
/// release builds use generic messages.
#[cfg(feature = "encoding-hex")]
pub use error::HexError;

/// Unified error type wrapping format-specific decoding errors ([`HexError`],
/// [`Base64Error`], [`Bech32Error`]). Always available; variants depend on enabled features.
pub use error::DecodingError;

/// Error returned when a byte slice cannot be converted to `Fixed<[u8; N]>` due to
/// length mismatch. Produced by `Fixed::try_from(&[u8])`.
pub use error::FromSliceError;
