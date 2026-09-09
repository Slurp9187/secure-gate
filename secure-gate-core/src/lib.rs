// no_std by default; the `std` feature opts back into the standard library.
// Verified in CI by cross-building for a bare-metal target.
#![cfg_attr(not(feature = "std"), no_std)]
// Forbid unsafe code unconditionally
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Secure wrappers for secrets with **explicit access** and **mandatory zeroization** — a
//! `no_std`-compatible, zero-overhead library with audit-friendly access patterns.
//!
//! Secrets are **automatically zeroized on drop** (the inner type must implement
//! [`Zeroize`](zeroize::Zeroize)). While a secret is held in [`Fixed`] or [`Dynamic`],
//! there is no `Deref` and no `AsRef`: callers reach the inner secret only via
//! [`RevealSecret`] / [`RevealSecretMut`], and `Debug` always prints `[REDACTED]`.
//! Access has two shapes: **borrow** it, or **take** it.
//! [`with_secret()`](RevealSecret::with_secret) and
//! [`expose_secret()`](RevealSecret::expose_secret) lend you a reference while the
//! wrapper keeps ownership and keeps wiping. [`into_inner()`](RevealSecret::into_inner)
//! transfers ownership: you get the plain value and the protection ends with the call.
//!
//! Those two shapes are what the **3-tier access model** in `SECURITY.md` counts in
//! threes: `with_secret` (Tier 1) and `expose_secret` (Tier 2) are both the borrow
//! shape, differing only in how tightly the lifetime is pinned, and `into_inner`
//! (Tier 3) is the take. Two shapes, three volumes — the tiers say how loudly you
//! have to announce which one you picked, not how many protections there are.
//!
//! Extraction is a hand-off, not a third layer of protection. Encoding output is the
//! one case that keeps a wrapper — [`EncodedSecret`] **does** implement `Deref`, because
//! its job is to keep an encoded *copy* of the secret wiped until it drops. Ordinary
//! copies you make of the derefed value (`.to_string()`) are not tracked. See
//! [Where accident-prevention ends](#where-accident-prevention-ends).
//!
//! # Which type should I use?
//!
//! | Type | Allocation | Use case | Feature |
//! |------|-----------|----------|----------|
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
//! │   │   └── EncodedSecret     ← zeroizing encoded string wrapper (alloc)
//! │   ├── ConstantTimeEq    ← ct-eq feature
//! │   ├── CloneableSecret   ← cloneable feature
//! │   ├── SerializableSecret← serde-serialize feature
//! │   ├── encoding/         ← ToHex, ToBase32, ToBase64Url, ToBech32, ToBech32m
//! │   └── decoding/         ← FromHexStr, FromBase32Str, FromBase64UrlStr, FromBech32Str, FromBech32mStr
//! ├── macros/               ← fixed_alias!, fixed_newtype!, dynamic_alias!, dynamic_newtype!, etc.
//! └── error                 ← FromSliceError, HexError, Base32Error, Base64Error, Bech32Error
//! ```
//!
//! All public items are re-exported at the crate root. Use `secure_gate::Fixed`,
//! not `secure_gate::fixed::Fixed`.
//!
//! # Type taxonomy
//!
//! | Category | Types | `Deref` to secret? | Purpose |
//! |----------|-------|-------------------|----------|
//! | **Secret wrappers** | [`Fixed<T>`], [`Dynamic<T>`] | No — use [`RevealSecret`] | Hold live secrets; `Debug` → `[REDACTED]` |
//! | **Output wrapper** | [`EncodedSecret`] | Yes — yields `&str`; copies you make are yours, the buffer stays the wrapper's | Holds encoded output, wiped on drop |
//! | **Opt-in markers** | [`CloneableSecret`], [`SerializableSecret`] | — (no methods) | Implement on inner type `T` to unlock gated impls |
//!
//! `CloneableSecret` and `SerializableSecret` are implemented on the **inner type `T`**,
//! not on `Fixed<T>` or `Dynamic<T>` directly. [`EncodedSecret`] is not a secret
//! wrapper and does not interact with these markers.
//!
//! # Where accident-prevention ends
//!
//! This crate carries two separate obligations, and they end in different places.
//!
//! **Accidents must not compile.** This applies while the secret is held in
//! [`Fixed`]/[`Dynamic`], and it ends at the named extraction. `into_inner` and
//! `EncodedSecret::into_inner` are the exits that transfer ownership: you typed a
//! name, the call site is grep-able, and the wrapper is consumed. `expose_secret` is
//! a named *borrow* — the wrapper still owns the secret and still wipes it — but it
//! hands out a reference with no lifetime bound to a call site, so it is audited
//! alongside them.
//!
//! **Documented behavior must be accurate.** This never ends, and it is why the
//! taxonomy table above says `Deref: Yes` for the output wrapper.
//!
//! What [`EncodedSecret`] still guarantees: the `String` it owns is zeroized on drop,
//! and its `Debug` prints `[REDACTED]`. What it does not guarantee: copies you make
//! through `Deref` are ordinary values. `str::to_string()` and `.to_owned()` both
//! produce untracked plaintext. That is what extraction is for — the crate is not
//! trying to follow the bytes into your TLS stack. `into_inner` gives up even the first
//! guarantee, by design: it is the named end of protection.
//!
//! Two consequences worth knowing:
//!
//! - `format!("{:?}", &*encoded)` prints the encoded secret. Redaction lives on the
//!   wrapper, not on `str`; dereferencing first opts out of it.
//! - [`EncodedSecret::into_zeroizing`] returns a `Zeroizing<String>`, whose `Debug` is
//!   **not** redacted. It is a deliberate hand-off to a foreign type, not an equivalent
//!   wrapper.
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
//! | **Wrapper trait impl** (ergonomic) | `key.to_hex()` (needs `use secure_gate::ToHex`) | No — grep for `to_hex` directly |
//! | **Trait via scoped access** (audit-friendly) | `key.with_secret(\|b\| b.to_hex())` | Yes — `with_secret` is grep-able |
//!
//! Both levels are impls of the **same** trait ([`ToHex`], [`ToBase32`], [`ToBase64Url`],
//! [`ToBech32`], [`ToBech32m`]): a blanket impl covers the raw bytes inside
//! `with_secret`, and per-wrapper impls on `Fixed<[u8; N]>` / `Dynamic<Vec<u8>>`
//! delegate through `with_secret` internally. One trait also means one bound:
//! `fn fingerprint<S: ToHex>(s: &S)` accepts wrappers and forwarding newtypes
//! alike.
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
//! | `encoding-base32` | no | [`ToBase32`] / [`FromBase32Str`] via `base32ct` (constant-time) |
//! | `encoding-base64` | no | [`ToBase64Url`] / [`FromBase64UrlStr`] via `base64ct` (constant-time) |
//! | `encoding-bech32` | no | [`ToBech32`] / [`FromBech32Str`] (BIP-173) **and** [`ToBech32m`] / [`FromBech32mStr`] (BIP-350); `_sized::<N>` for a caller-chosen code length |
//! | `encoding` | no | All encoding features |
//! | | | **Meta** |
//! | `cloneable` | no | [`CloneableSecret`] opt-in cloning |
//! | `full` | no | Everything |
//!
//! # What's available without `alloc`?
//!
//! With `default-features = false`:
//! - [`Fixed<T>`], [`RevealSecret`], [`RevealSecretMut`]
//! - [`Fixed::try_from_hex`](Fixed::try_from_hex), [`Fixed::try_from_base32`](Fixed::try_from_base32),
//!   [`Fixed::try_from_base64url`](Fixed::try_from_base64url),
//!   [`Fixed::try_from_bech32`](Fixed::try_from_bech32), [`Fixed::try_from_bech32m`](Fixed::try_from_bech32m)
//!   (no-alloc stack-based decoding)
//! - [`fixed_alias!`], [`fixed_generic_alias!`] (type aliases), and
//!   [`fixed_newtype!`] (distinct nominal types — two keys of the same size that
//!   the compiler keeps apart)
//! - [`FromSliceError`]
//!
//! **Not** available without `alloc`: [`Dynamic<T>`], [`EncodedSecret`],
//! encoding traits ([`ToHex`], etc.), decoding traits ([`FromHexStr`], etc.),
//! [`dynamic_alias!`], [`dynamic_generic_alias!`], [`dynamic_newtype!`], serde support.
//!
//! # `no_std`
//!
//! `no_std` compatible (`#![no_std]` unless the `std` feature is enabled — verified in CI
//! by cross-building for `thumbv7em-none-eabihf`). [`Fixed<T>`] works without `alloc`.
//! Enable `alloc` (default) for [`Dynamic<T>`]. For pure stack / embedded builds, use
//! `default-features = false`. MSRV: **1.70** (Rust edition 2021, LTS line).
//!
//! One caveat: the `rand` feature compiles without `std` or `alloc`, but
//! [`Fixed::from_random`] relies on `getrandom`, which needs a platform entropy backend.
//! On bare-metal targets you must configure one (see the `getrandom` crate's
//! "custom backend" documentation); without it, builds enabling `rand` fail at link
//! time on such targets. [`Fixed::from_rng`] with a caller-supplied RNG has no such
//! requirement.
//!
//! # Security
//!
//! This crate has **not** undergone an independent security audit. No unsafe code —
//! enforced with `#![forbid(unsafe_code)]`. Prefer scoped access ([`RevealSecret::with_secret`])
//! over direct references. Encoders return [`EncodedSecret`], which stays wiped until it
//! drops; `EncodedSecret::into_inner` is the named call that ends that. See
//! [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/release/0.8/secure-gate-core/SECURITY.md)
//! for the full threat model.
//!
//! # Inherent Rust Limitations
//!
//! Three universal limits apply to any in-memory secret library in Rust (and in
//! C, C++, and Go) — `secure-gate` documents them honestly rather than
//! overclaiming:
//!
//! - **Stack-move residue**: moving a [`Fixed<T>`] by value leaves the prior stack
//!   slot uncleared until a later frame overwrites it. Prefer
//!   [`Fixed::new_with`](Fixed::new_with), pass by reference, or use
//!   [`Dynamic<T>`] for long-lived secrets.
//! - **Heap-reallocation residue**: `Vec` / `String` realloc frees the old buffer
//!   unzeroed. Pre-size, use `Dynamic<[u8; N]>` (boxed array — no realloc surface),
//!   or install a zero-on-dealloc global allocator such as `zeroizing-alloc` at
//!   the binary level.
//! - **Swap / core dumps**: process memory paged to disk or written on crash is
//!   outside any in-process library's reach. Use OS facilities (`mlock`,
//!   encrypted swap, disabled core dumps).
//!
//! Full discussion in
//! [SECURITY.md § Inherent Rust Limitations](https://github.com/Slurp9187/secure-gate/blob/release/0.8/secure-gate-core/SECURITY.md#inherent-rust-limitations).
//!
//! See the [README](https://github.com/Slurp9187/secure-gate/blob/main/README.md) and
//! [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/release/0.8/secure-gate-core/SECURITY.md) for full details.

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

/// Implementation detail of the `*_newtype!` macros — not a public API.
///
/// Generated code needs to name `Zeroize`, `serde` traits, and `alloc` types
/// without requiring the caller to depend on those crates directly, and
/// `::alloc::…` paths do not resolve in an ordinary `std` crate. Re-exporting
/// them here keeps expansions self-contained via `$crate::__private::…`.
///
/// Semver-exempt: items here may change or disappear in any release.
#[doc(hidden)]
pub mod __private {
    #[cfg(feature = "alloc")]
    pub use alloc::{boxed::Box, string::String, vec::Vec};
    #[cfg(feature = "rand")]
    pub use rand::{TryCryptoRng, TryRngCore};
    #[cfg(feature = "serde-deserialize")]
    pub use serde::{Deserialize, Deserializer};
    #[cfg(feature = "serde-serialize")]
    pub use serde::{Serialize, Serializer};
    pub use zeroize::{Zeroize, ZeroizeOnDrop};
}

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

/// Cursor-like reader over [`Dynamic<Vec<u8>>`] — see [`Dynamic::as_reader`].
#[cfg(feature = "std")]
pub use dynamic::DynamicReader;

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
/// Implement this on your inner type `T`; `Fixed<T>` and `Dynamic<T>` then gain the
/// gated `Clone` impl automatically. **This marker is deliberately not implemented by
/// default** on `Fixed<T>` or `Dynamic<T>` — cloning is an opt-in risk that must be
/// explicitly enabled. Without the `cloneable` feature this type does not exist at all.
///
///
/// **Coherence note:** Rust's orphan rule prevents downstream crates from implementing
/// this marker for foreign types such as `String`, `Vec<u8>`, or `[u8; N]` — so
/// `Dynamic<String>` and `Fixed<[u8; N]>` themselves can never become `Clone`. To opt
/// a secret into cloning, define a newtype inner type in your crate (deriving
/// `Zeroize` and `Clone`) and implement the marker on it. This is intentional: it keeps
/// every cloneable secret type visible in *your* code. See the trait-level docs for a
/// worked example.
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
/// - **Tier 3** (consumption): [`into_inner()`](RevealSecret::into_inner) — transfers
///   ownership of the plain value; protection ends with the call.
///
/// Length metadata lives in the separate [`SecretLen`] trait. See
/// [`RevealSecretMut`] for the mutable counterpart.
// Kept as a separate `use` from `SecretLen` on purpose: rustdoc 1.70 (the 0.8
// line's MSRV toolchain) ICEs resolving intra-doc links on a grouped
// `pub use a::{B, C};` re-export, and the two lines share this file.
pub use traits::RevealSecret;

/// Length metadata for secrets whose inner type has a meaningful length.
///
/// [`len()`](SecretLen::len) / [`byte_len()`](SecretLen::byte_len) /
/// [`is_empty()`](SecretLen::is_empty) do not expose contents, but length itself
/// can be sensitive for variable-length secrets — see the trait's Security
/// section. Implemented for `Fixed<[T; N]>`, `Dynamic<String>`, and
/// `Dynamic<Vec<T>>`; deliberately not for custom inner types.
pub use traits::SecretLen;

/// Explicit mutable access to secret contents.
///
/// Extends [`RevealSecret`]. Prefer [`with_secret_mut()`](RevealSecretMut::with_secret_mut)
/// (Tier 1) over [`expose_secret_mut()`](RevealSecretMut::expose_secret_mut) (Tier 2).
/// Implemented by [`Fixed`], [`Dynamic`], and the generated newtypes. [`EncodedSecret`]
/// implements neither this nor [`RevealSecret`] — it is an output wrapper, not a secret one.
pub use traits::RevealSecretMut;

/// Placeholder values left behind by [`RevealSecret::into_inner`] (Tier 3 access).
///
/// When `into_inner` moves the real secret out of a wrapper, it must leave *something*
/// behind for the wrapper's `Drop` impl to zeroize. `SentinelValue::sentinel_value()`
/// produces that inert placeholder (an all-default array, empty `String`, or empty
/// `Vec`). Implemented for `[T; N]` (any `N`, `T: Default`), `String`, and `Vec<T>`.
///
/// Implement this for your own inner types to make `into_inner` available on wrappers
/// around them. A sentinel must never contain secret material.
///
/// Leaving it unimplemented is a deliberate position, not a gap: `into_inner` is then
/// uncallable for that inner type, so a secret with no safe inert placeholder simply
/// cannot be extracted by ownership transfer. `with_secret` and `expose_secret` still
/// work. That is the safe default rather than a missing feature.
pub use traits::SentinelValue;

/// Encoded string **output wrapper** for zeroizing encoded output.
///
/// This is an **output wrapper** — it exists *only* to keep encoded data zeroized until
/// it drops. It is **not** a secret wrapper like [`Fixed`]/[`Dynamic`] and does not
/// accept [`CloneableSecret`] or [`SerializableSecret`] markers.
///
/// Returned by every encoding method (`to_hex`, `to_hex_upper`, `to_base32`,
/// `to_base64url`, `try_to_bech32`, `try_to_bech32m`, and the `_sized::<N>` forms of
/// the last two — only bech32 and bech32m take a code length).
/// Wraps `Zeroizing<String>` with `Debug` → `[REDACTED]`. Its one accessor is
/// `Deref<Target = str>`; there are deliberately no `AsRef` impls, because `Deref`
/// already opens that door. Deliberately **no** `Display` either: `{}` on this type is
/// a compile error, so `Debug` redaction cannot mislead a caller into logging the
/// encoded secret. Write it out with `&*encoded`.
///
/// Use [`into_inner()`](EncodedSecret::into_inner) to extract a plain `String`
/// (ends zeroization) or [`into_zeroizing()`](EncodedSecret::into_zeroizing) to keep
/// the wiping. `into_zeroizing` is a partial downgrade: zeroize-on-drop survives, the
/// redacted `Debug` does not, because `zeroize::Zeroizing` derives its own.
///
/// Requires `alloc` feature.
#[cfg(feature = "alloc")]
pub use traits::EncodedSecret;

/// Marker trait that opts a secret type into Serde serialization. No methods — gates the
/// `Serialize` impl on [`Fixed`] and [`Dynamic`]. Serialization exposes the full secret;
/// audit every impl. Requires `serde-serialize` feature.
///
/// **`Deserialize` does NOT require this marker** — it is gated separately by the
/// `serde-deserialize` feature with its own impls on the wrapper types directly. This
/// marker controls `Serialize` only.
///
/// Implement this on your inner type `T`; `Fixed<T>` and `Dynamic<T>` then gain the
/// gated `Serialize` impl automatically. **This marker is deliberately not implemented
/// by default** on `Fixed<T>` or `Dynamic<T>` — serialization is an opt-in risk that
/// must be explicitly enabled. Without the `serde-serialize` feature this type does not
/// exist at all.
///
///
/// **Coherence note:** Rust's orphan rule prevents downstream crates from implementing
/// this marker for foreign types such as `String`, `Vec<u8>`, or `[u8; N]` — so
/// `Fixed<[u8; N]>` and `Dynamic<String>` themselves can never become `Serialize`. To
/// opt a secret into serialization, define a newtype inner type in your crate (deriving
/// `Zeroize` and `Serialize`) and implement the marker on it. This is intentional: it
/// keeps every serializable secret type visible in *your* code. See the trait-level
/// docs for a worked example.
/// See also [`CloneableSecret`] (the other opt-in marker trait).
#[cfg(feature = "serde-serialize")]
pub use traits::SerializableSecret;

// Type alias macros (always available)
mod macros;

/// Decodes Base32 strings (`&str`) to `Vec<u8>`. Blanket impl for `AsRef<str>`.
/// Requires `encoding-base32` + `alloc`. See [`ToBase32`] for the encoding counterpart.
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
pub use traits::FromBase32Str;

/// Decodes Base64url strings (`&str`) to `Vec<u8>`. Blanket impl for `AsRef<str>`.
/// Requires `encoding-base64` + `alloc`. See [`ToBase64Url`] for the encoding counterpart.
#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub use traits::FromBase64UrlStr;

/// Decodes Bech32 (BIP-173) strings to `Vec<u8>` with HRP validation.
/// Requires `encoding-bech32` + `alloc`. See [`ToBech32`] for the encoding counterpart.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use traits::FromBech32Str;

/// Decodes Bech32m (BIP-350) strings to `Vec<u8>` with HRP validation.
/// Requires `encoding-bech32` + `alloc`. See [`ToBech32m`] for the encoding counterpart.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use traits::FromBech32mStr;

/// Decodes hex strings (`&str`) to `Vec<u8>`. Blanket impl for `AsRef<str>`.
/// Requires `encoding-hex` + `alloc`. See [`ToHex`] for the encoding counterpart.
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
pub use traits::FromHexStr;

/// Encodes byte data as Base32 strings (RFC 4648 §6, uppercase, no padding).
/// Blanket impl for `AsRef<[u8]> + `[`EncodableBytes`]. Returns [`EncodedSecret`].
/// Requires `encoding-base32` + `alloc`.
/// See [`FromBase32Str`] for the decoding counterpart.
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
pub use traits::ToBase32;

/// Encodes byte data as Base64url strings (RFC 4648, URL-safe, no padding).
/// Blanket impl for `AsRef<[u8]> + `[`EncodableBytes`]. Returns [`EncodedSecret`].
/// Requires `encoding-base64` + `alloc`.
/// See [`FromBase64UrlStr`] for the decoding counterpart.
#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub use traits::ToBase64Url;

/// Encodes byte data as Bech32 (BIP-173) strings. Blanket impl for
/// `AsRef<[u8]> + `[`EncodableBytes`]; returns `Result<`[`EncodedSecret`]`, _>`.
/// The plain methods use [`BECH32_CODE_LENGTH`]; `try_to_bech32_sized::<N>` takes the
/// code length as a parameter. Requires `encoding-bech32` + `alloc`.
/// See [`FromBech32Str`] for the decoding counterpart.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use traits::ToBech32;

/// Encodes byte data as Bech32m (BIP-350) strings. Blanket impl for
/// `AsRef<[u8]> + `[`EncodableBytes`]; returns `Result<`[`EncodedSecret`]`, _>`.
/// The plain methods use [`BECH32_CODE_LENGTH`]; `try_to_bech32m_sized::<N>` takes the
/// code length as a parameter. Requires `encoding-bech32` + `alloc`.
/// See [`FromBech32mStr`] for the decoding counterpart.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use traits::ToBech32m;

/// Opt-in marker for byte-shaped encoding inputs. Every `To*` trait is blanket
/// implemented for `AsRef<[u8]> + EncodableBytes`; the second bound keeps string-shaped
/// types out, so an already-encoded value cannot be silently encoded again. Implement it
/// for your own byte newtype to make it encodable.
#[cfg(feature = "encoding-bech32")]
pub use traits::Case;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
pub use traits::EncodableBytes;

/// Bech32 (BIP-173) checksum with a caller-chosen code length. `N` caps the length of
/// the whole encoded string and never enters the checksum. Above [`BECH32_CODE_LENGTH`]
/// the BCH error-detection guarantee no longer holds - see the type docs.
// Kept as separate `use` statements on purpose: rustdoc 1.70 (this line's MSRV
// toolchain) ICEs resolving intra-doc links on a grouped `pub use a::{B, C};`
// re-export — the same bug already worked around for `SecretLen` above.
#[cfg(feature = "encoding-bech32")]
pub use traits::Bech32Sized;

/// The BIP-173 checksum at the default code length, used by every non-`_sized` method.
#[cfg(feature = "encoding-bech32")]
pub use traits::Bech32Standard;

/// Bech32m (BIP-350) checksum with a caller-chosen code length - the bech32m twin of
/// [`Bech32Sized`], with the same rules and the same guarantee boundary.
#[cfg(feature = "encoding-bech32")]
pub use traits::Bech32mSized;

/// The BIP-350 checksum at the default code length, used by every non-`_sized` method.
#[cfg(feature = "encoding-bech32")]
pub use traits::Bech32mStandard;

/// The bech32 BCH code length (1023) used by every non-`_sized` method.
#[cfg(feature = "encoding-bech32")]
pub use traits::BECH32_CODE_LENGTH;

/// Sizes an `N` for the `_sized` methods from an HRP length and a payload byte count.
#[cfg(feature = "encoding-bech32")]
pub use traits::bech32_code_length;

/// Encodes byte data as hexadecimal strings (constant-time via `base16ct`).
/// Blanket impl for `AsRef<[u8]> + `[`EncodableBytes`]. Provides `to_hex()` and
/// `to_hex_upper()`, both returning [`EncodedSecret`].
/// Requires `encoding-hex` + `alloc`.
/// See [`FromHexStr`] for the decoding counterpart.
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
pub use traits::ToHex;

/// Marker trait for types that support secure decoding (`AsRef<str>`). No methods —
/// nothing bounds on it — the `From*Str` blankets are plain `AsRef<str>`. Retained for
/// backwards compatibility; the 0.9 line removed it.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
pub use traits::SecureDecoding;

/// Vestigial marker for byte-shaped types (`AsRef<[u8]>`). No methods, and nothing
/// bounds on it — the `To*` blankets are gated by [`EncodableBytes`]. Retained for
/// backwards compatibility; the 0.9 line removed it.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
pub use traits::SecureEncoding;

/// Errors from Bech32 (BIP-173) and Bech32m (BIP-350) decoding.
/// Variant shapes are identical in debug and release builds; no secret material
/// (payload bytes, HRP strings) is ever carried in an error.
#[cfg(feature = "encoding-bech32")]
pub use error::Bech32Error;

/// Errors from Base32 (RFC 4648 §6, uppercase, unpadded) decoding. Variant shapes are
/// identical in debug and release builds; only numeric length metadata is carried.
#[cfg(feature = "encoding-base32")]
pub use error::Base32Error;

/// Errors from Base64url decoding. Variant shapes are identical in debug and
/// release builds; only numeric length metadata is carried.
#[cfg(feature = "encoding-base64")]
pub use error::Base64Error;

/// Errors from hex decoding. Variant shapes are identical in debug and
/// release builds; only numeric length metadata is carried.
#[cfg(feature = "encoding-hex")]
pub use error::HexError;

/// Error returned when a byte slice cannot be converted to `Fixed<[u8; N]>` due to
/// length mismatch. Produced by `Fixed::try_from(&[u8])`.
pub use error::FromSliceError;

// The README's examples are compiled and run by `cargo test --doc`, so they cannot
// silently rot. `cfg(doctest)` is set only while rustdoc *collects doctests* — never
// while it *builds documentation* — so this item never reaches docs.rs or `cargo doc`
// output, and the README is not duplicated onto the crate page.
//
// Gated on `full` as well: the README documents the fully-featured crate, so its
// examples use `alloc` and the encoding traits unconditionally. Without this gate the
// `--no-default-features` doctest job in CI would fail on imports the README does not
// feature-gate. CI's `--features full` and `--all-features` entries do run them.
//
// It must live at the end of the file: an item here would otherwise sit ahead of the
// `//!` crate docs above, which is not allowed.
#[cfg(all(doctest, feature = "full"))]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
