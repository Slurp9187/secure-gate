// no_std by default; the `std` feature opts back into the standard library.
// Verified in CI by cross-building for a bare-metal target.
#![cfg_attr(not(feature = "std"), no_std)]
// Forbid unsafe code unconditionally
#![forbid(unsafe_code)]
#![warn(missing_docs)]
// `Cargo.toml` tells docs.rs to build with `--cfg docsrs`. This is what reads it:
// `doc_cfg` annotates every feature-gated item with the feature that enables it, so
// the docs people read say "Available on crate feature `encoding-hex`" instead of
// leaving the reader to infer it. Nightly-only, which is fine — docs.rs builds on
// nightly, and the only other build that sets `docsrs` is the CI step that exists to
// catch this gate being renamed. It has been renamed before: `doc_auto_cfg` was the
// spelling until 1.92 removed it and merged it into `doc_cfg`.
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Secure wrappers for secrets with **explicit access** and **mandatory zeroization** — a
//! `no_std`-compatible, zero-overhead library with audit-friendly access patterns.
//!
//! Secrets are **automatically zeroized on drop** (the inner type must implement
//! [`Zeroize`](zeroize::Zeroize)). While a secret is held in [`Fixed`] or [`Dynamic`],
//! there is no `Deref` and no `AsRef`: callers reach the inner secret only via
//! [`RevealSecret`] / [`RevealSecretMut`], and `Debug` on a wrapper always prints
//! `[REDACTED]`. [`SlotWriter`], which borrows a wrapper's storage rather than holding it,
//! prints its cursor instead — position, remaining, length — and never the bytes.
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
//! |------|-----------|----------|---------|
//! | [`Fixed<T>`] | Stack | Keys, nonces, tokens — compile-time-known size | Always available |
//! | [`Dynamic<T>`] | Heap | Passwords, API keys, ciphertexts — variable length | `alloc` (default) |
#![cfg_attr(
    feature = "sealed",
    doc = "| [`SealedFixed<N>`](SealedFixed) / [`SealedDynamic<T>`](SealedDynamic) | Encrypted in RAM while idle, under a guarded, locked [`Prekey`] | Long-held keys in a process whose memory may be read while they idle | `sealed` |"
)]
#![cfg_attr(
    not(feature = "sealed"),
    doc = "| `SealedFixed<N>` / `SealedDynamic<T>` | Encrypted in RAM while idle, under a guarded, locked `Prekey` | Long-held keys in a process whose memory may be read while they idle | `sealed` |"
)]
//!
//! `Fixed` and `Dynamic` share the same [`RevealSecret`] / [`RevealSecretMut`] access API.
//! The sealed types are opened only through scoped `with_secret` calls (no `expose_secret`),
//! cost about 8 µs per access, and are for keys held across a session, not hot loops; their
//! module has the threat model and the measurements.
//!
//! (The row above is a real intra-doc link where `sealed` is enabled, as on docs.rs, and
//! plain text where it is not, so builds without the feature have no broken link.)
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
//! use secure_gate::{fixed_newtype, RevealSecret};
//!
//! fixed_newtype!(pub Aes256Key, 32);
//!
//! let key = Aes256Key::new([0xABu8; 32]);
//! key.with_secret(|b| assert_eq!(b.len(), 32));
//! ```
//!
//! # Module structure
//!
//! ```text
//! secure_gate (lib.rs)
//! ├── Fixed<T>              ← always available, stack-allocated
//! ├── Dynamic<T>            ← requires `alloc`, heap-allocated
//! ├── SlotWriter            ← cursor a sized `new_with` hands out (alloc)
//! ├── traits/
//! │   ├── RevealSecret      ← immutable access (always available)
//! │   ├── RevealSecretMut   ← mutable access (always available)
//! │   ├── SecretLen         ← length metadata (always available)
//! │   ├── SentinelValue     ← placeholder `into_inner` leaves behind (always available)
//! │   ├── FixedStorage      ← marker `Fixed::new` requires (always available)
//! │   ├── EncodedSecret     ← zeroizing encoded string wrapper (alloc)
//! │   ├── ConstantTimeEq    ← ct-eq feature
//! │   ├── CloneableSecret   ← cloneable feature
//! │   ├── SerializableSecret← serde-serialize feature
//! │   └── encoding/         ← ToHex, ToBase32, ToBase64Url, ToBech32, ToBech32m,
//! │                           EncodableBytes
//! │                           (decoding: the `try_from_*` constructors on Fixed / Dynamic)
//! ├── sealed/               ← SealedFixed, SealedDynamic, Prekey, LockError (sealed feature)
//! ├── scoped                ← RevealScoped (sealed feature; not at the root, see below)
//! ├── macros/               ← fixed_newtype!, dynamic_newtype!, sealed_fixed_newtype!
//! └── error                 ← FromSliceError, HexError, Base32Error, Base64Error, Bech32Error
//! ```
//!
//! Every public item is re-exported at the crate root, with two exceptions that are
//! imported from their modules: [`scoped::RevealScoped`], whose `with_secret` would
//! collide with [`RevealSecret::with_secret`] if both were in scope, and
//! `sealed::SealedPayload`, the trait that bounds what `SealedDynamic` can hold. Use
//! `secure_gate::Fixed`, not `secure_gate::fixed::Fixed`.
//!
//! # Type taxonomy
//!
//! | Category | Types | `Deref` to secret? | Purpose |
//! |----------|-------|-------------------|---------|
//! | **Secret wrappers** | [`Fixed<T>`], [`Dynamic<T>`] | No — use [`RevealSecret`] | Hold live secrets; `Debug` → `[REDACTED]` |
//! | **Output wrapper** | [`EncodedSecret`] | Yes — yields `&str`; copies you make are yours, the buffer stays the wrapper's | Holds encoded output, wiped on drop |
//! | **Borrowed slot cursor** | [`SlotWriter`] | No — it writes, it does not read out | Appends into a slot a sized `new_with` handed out; `Debug` → cursor state only, never bytes |
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
//! - [`EncodedSecret::into_zeroizing`] returns a `Zeroizing<String>`. It keeps the wipe,
//!   and its `Debug` is opaque (`zeroize` ≥ 1.9.1, which this crate requires), but it
//!   derefs to `String`. It is a deliberate hand-off to a foreign type, not an
//!   equivalent wrapper.
//!
//! # Import paths
//!
//! ```rust
//! // ✅ Correct — always import from the crate root
//! use secure_gate::{Fixed, RevealSecret};
//!
//! // ❌ Wrong — these deeper paths compile, but the stability promise does not cover them
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
//! | `rand` | no | `from_random()` (system RNG) — `no_std` for [`Fixed`] |
//! | `sealed` | no | `SealedFixed` / `SealedDynamic`: secrets encrypted in RAM while idle, under a locked `Prekey` (implies `std`, `rand`) |
//! | | | **Serialization** |
//! | `serde-serialize` | no | Serde `Serialize` (requires [`SerializableSecret`] marker) |
//! | `serde-deserialize` | no | Serde `Deserialize` with 1 MiB default limit |
//! | `serde` | no | Both directions |
//! | | | **Encoding** |
//! | `encoding-hex` | no | [`ToHex`] / `try_from_hex` via `base16ct` (constant-time) |
//! | `encoding-base32` | no | [`ToBase32`] / `try_from_base32` via `base32ct` (constant-time) |
//! | `encoding-base64` | no | [`ToBase64Url`] / `try_from_base64url` via `base64ct` (constant-time) |
//! | `encoding-bech32` | no | [`ToBech32`] / `try_from_bech32` (BIP-173) **and** [`ToBech32m`] / `try_from_bech32m` (BIP-350); `_sized::<N>` for a caller-chosen code length |
//! | `encoding` | no | All encoding features |
//! | | | **Meta** |
//! | `cloneable` | no | [`CloneableSecret`] opt-in cloning |
//! | `full` | no | Everything except `std` and `sealed` |
//!
//! # What's available without `alloc`?
//!
//! With `default-features = false`:
//! - [`Fixed<T>`], [`RevealSecret`], [`RevealSecretMut`]
//! - [`Fixed::try_from_hex`](Fixed::try_from_hex), [`Fixed::try_from_base32`](Fixed::try_from_base32),
//!   [`Fixed::try_from_base64url`](Fixed::try_from_base64url),
//!   [`Fixed::try_from_bech32`](Fixed::try_from_bech32), [`Fixed::try_from_bech32m`](Fixed::try_from_bech32m)
//!   (no-alloc stack-based decoding)
//! - [`fixed_newtype!`] (distinct nominal types — two keys of the same size that
//!   the compiler keeps apart); a plain `type` alias over [`Fixed<T>`] needs nothing
//!   at all
//! - [`FromSliceError`]
//!
//! **Not** available without `alloc`: [`Dynamic<T>`], [`EncodedSecret`],
//! encoding traits ([`ToHex`], etc.), the `Dynamic::try_from_*` decoders,
//! [`dynamic_newtype!`], serde support.
//!
//! # `no_std`
//!
//! `no_std` compatible (`#![no_std]` unless the `std` feature is enabled — verified in CI
//! by cross-building for `thumbv7em-none-eabihf`). [`Fixed<T>`] works without `alloc`.
//! Enable `alloc` (default) for [`Dynamic<T>`]. For pure stack / embedded builds, use
//! `default-features = false`. MSRV: **1.87** (Rust edition 2024).
//!
//! One caveat: the `rand` feature compiles without `std` or `alloc`, but
//! [`Fixed::from_random`] relies on `getrandom`, which needs a platform entropy backend.
//! On bare-metal targets you must configure one (see the `getrandom` crate's
//! "custom backend" documentation); without it, builds enabling `rand` fail at link
//! time on such targets. Filling from a caller-supplied RNG through
//! [`Fixed::try_new_with`] has no such requirement, and needs no feature at all.
//!
//! # Security
//!
//! This crate has **not** undergone an independent security audit. No unsafe code —
//! enforced with `#![forbid(unsafe_code)]`. Prefer scoped access ([`RevealSecret::with_secret`])
//! over direct references. Encoders return [`EncodedSecret`], which stays wiped until it
//! drops; `EncodedSecret::into_inner` is the named call that ends that. See
//! [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md)
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
//! [SECURITY.md § Inherent Rust Limitations](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md#inherent-rust-limitations).
//!
//! See the [README](https://github.com/Slurp9187/secure-gate/blob/main/README.md) and
//! [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for full details.

#[cfg(feature = "alloc")]
extern crate alloc;

// Documentation-only. Several doc comments link to `std` items this crate touches through
// gated impls (`io::Write` on `Dynamic<Vec<u8>>` and on `SlotWriter`, `io::Read` on
// `DynamicReader`). Those links are correct and resolve on docs.rs, which builds with
// `all-features`, and in CI, whose rustdoc job does the same. They do NOT resolve under
// `--features=full`, which does not enable `std`: without that feature the name `std` is
// not in scope at all, so rustdoc has nothing to point at and `-D warnings` turns each one
// into an error. That is a plain `cargo doc --features full` — something a contributor
// runs and CI does not. This brings the name into scope for doc builds only: it is
// `cfg(doc)`, set by rustdoc and nothing else, so no real build is affected, `no_std` or
// otherwise, and the links resolve in every feature combination rather than only the one
// docs.rs happens to use.
#[cfg(doc)]
extern crate std;

#[cfg(all(
    feature = "alloc",
    any(
        feature = "encoding-hex",
        feature = "encoding-base32",
        feature = "encoding-base64"
    )
))]
mod decode_staging;
#[cfg(feature = "alloc")]
mod dynamic;

mod slot_writer;

/// Fixed-size secret wrapper types - always available with zero dependencies.
/// These provide fundamental secure storage abstractions for fixed-size data.
mod fixed;

/// Centralized error types - always available.
mod error;

/// Core traits for wrapper polymorphism - always available.
pub mod traits;

#[cfg(feature = "sealed")]
pub mod sealed;

#[cfg(feature = "sealed")]
pub mod scoped;

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
    #[cfg(feature = "serde-deserialize")]
    pub use serde::{Deserialize, Deserializer};
    #[cfg(feature = "serde-serialize")]
    pub use serde::{Serialize, Serializer};
    pub use zeroize::{Zeroize, ZeroizeOnDrop};

    #[cfg(feature = "sealed")]
    pub use alloc::sync::Arc;

    /// A `fixed_newtype!` byte role, convertible to and from the `Fixed` it wraps without
    /// copying the bytes out by hand. Lets `sealed_fixed_newtype!` seal a role directly.
    #[cfg(feature = "sealed")]
    pub trait FixedRole: Sized {
        /// The wrapped `Fixed<[u8; N]>`.
        type Fixed: SealableFixed;
        /// Unwraps the role.
        fn into_fixed(self) -> Self::Fixed;
        /// Wraps a `Fixed` as the role.
        fn from_fixed(fixed: Self::Fixed) -> Self;
    }

    /// Maps `Fixed<[u8; N]>` to `SealedFixed<N>` without naming `N`.
    #[cfg(feature = "sealed")]
    pub trait SealableFixed {
        /// `SealedFixed<N>`.
        type Sealed;
    }

    #[cfg(feature = "sealed")]
    impl<const N: usize> SealableFixed for crate::Fixed<[u8; N]> {
        type Sealed = crate::SealedFixed<N>;
    }

    /// The `SealedFixed<N>` a role seals into.
    #[cfg(feature = "sealed")]
    pub type SealedOf<R> = <<R as FixedRole>::Fixed as SealableFixed>::Sealed;
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

#[cfg(feature = "sealed")]
#[doc(inline)]
pub use sealed::SealedFixed;

#[cfg(feature = "sealed")]
#[doc(inline)]
pub use sealed::SealedDynamic;

#[cfg(feature = "sealed")]
#[doc(inline)]
pub use sealed::Prekey;

#[cfg(feature = "sealed")]
#[doc(inline)]
pub use sealed::LockError;

/// Cursor-like reader over [`Dynamic<Vec<u8>>`] — see [`Dynamic::as_reader`].
#[cfg(feature = "std")]
pub use dynamic::DynamicReader;

/// Append-shaped writing into the fixed slot handed to a sized `new_with`.
///
/// The sized constructors hand out a slot whose length is already decided, which is what
/// makes growth — and therefore the reallocation hazard — inexpressible. `SlotWriter`
/// restores the append shape on top of that, so concatenating a wire format does not mean
/// writing offsets by hand. [`push_slice`](SlotWriter::push_slice) panics on overrun and
/// leaves the slot untouched; the `std`-gated [`Write`](std::io::Write) path cannot do that
/// and stay inside `Write`'s contract, so it truncates and reports the refusal on a later
/// call. `Debug` shows the cursor — position, remaining, length — and never the bytes.
pub use slot_writer::SlotWriter;

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

#[cfg(feature = "cloneable")]
#[doc(inline)]
pub use traits::CloneableSecret;

#[cfg(feature = "ct-eq")]
#[doc(inline)]
pub use traits::ConstantTimeEq;

// Kept as a separate `use` from `SecretLen` on purpose: rustdoc 1.70 (the 0.8
// line's MSRV toolchain) ICEs resolving intra-doc links on a grouped
// `pub use a::{B, C};` re-export, and the two lines share this file.
#[doc(inline)]
pub use traits::RevealSecret;

#[doc(inline)]
pub use traits::SecretLen;

#[doc(inline)]
pub use traits::RevealSecretMut;

#[doc(inline)]
pub use traits::SentinelValue;

#[doc(inline)]
pub use traits::FixedStorage;

#[cfg(feature = "alloc")]
#[doc(inline)]
pub use traits::EncodedSecret;

#[cfg(feature = "serde-serialize")]
#[doc(inline)]
pub use traits::SerializableSecret;

// Newtype macros (`dynamic_newtype!` needs `alloc`)
mod macros;

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
#[doc(inline)]
pub use traits::ToBase32;

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
#[doc(inline)]
pub use traits::ToBase64Url;

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
#[doc(inline)]
pub use traits::ToBech32;

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
#[doc(inline)]
pub use traits::ToBech32m;

#[cfg(feature = "encoding-bech32")]
#[doc(inline)]
pub use traits::Case;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
#[doc(inline)]
pub use traits::EncodableBytes;

#[cfg(feature = "encoding-bech32")]
#[doc(inline)]
pub use traits::{BECH32_CODE_LENGTH, bech32_code_length};

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
#[doc(inline)]
pub use traits::ToHex;

/// Errors from Bech32 (BIP-173) and Bech32m (BIP-350) encoding and decoding.
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
