# Plan: Base32 (RFC 4648) encoding via `base32ct`

| | |
|---|---|
| **Status** | **Shipped** in 0.9.0-rc.8 — PR [#164](https://github.com/Slurp9187/secure-gate/pull/164), commit `cf43e69`. Retained as a historical record; see the note below. |
| **Written as** | Proposed — revision 2, rebased on `0.9.0-rc.8` (the #155 newtype macros and the #156 `SecretLen` / trait-impl-encoder restructure) |
| **Tracking issue** | [#158](https://github.com/Slurp9187/secure-gate/issues/158) |
| **Target** | 0.9.0 or any later 0.9.x — additive, no breaking change |
| **Feature flag** | `encoding-base32` (folded into `encoding` → `full`) |
| **Backend** | [`base32ct`](https://github.com/RustCrypto/formats/tree/master/base32ct) 0.3.x (RustCrypto/formats) |
| **Sibling precedent** | `encoding-base64` / `base64ct` — this plan mirrors it file-for-file |

> **Historical record — not current documentation.**
>
> This document is kept for the reasoning it captures: why Base32 belongs in the crate
> (§2), the constant-time backend survey, the rejected alternatives, and the shape the
> implementation was held to. It is **not** a guide to the current tree.
>
> It was written against `0.9.0-rc.8` *before* the feature landed. Every line number in it
> is a snapshot of that moment and has since drifted. More importantly, one wiring step it
> prescribes was carried out and then deliberately undone in the same release cycle.
>
> Divergences identified so far are flagged inline as **\[Superseded]**. Nothing else in
> the text has been re-verified against the shipped code. For what the crate actually does
> today, read `secure-gate-core/src/traits/encoding/base32.rs`,
> `secure-gate-core/src/traits/decoding/base32.rs`, and the `encoding-base32` entries in
> `secure-gate-core/CHANGELOG.md`.

## 1. Goal

Add a fifth encoding format to `secure-gate-core`, Base32 per RFC 4648 §6, with exactly the
shape the four existing formats have after the #156 restructure:

- an encoding trait (`ToBase32`) with plain and `_zeroizing` methods — a blanket impl for
  `AsRef<[u8]>` **and** direct impls on the byte-shaped wrappers `Fixed<[u8; N]>` and
  `Dynamic<Vec<u8>>` that delegate through `with_secret` (one trait, one bound:
  `fn export<S: ToBase32>(s: &S)` accepts wrappers and forwarding newtypes alike);
- a decoding trait (`FromBase32Str`) blanket-implemented for `AsRef<str>`;
- inherent decode constructors `Fixed::try_from_base32` (with the no-alloc stack path) and
  `Dynamic::try_from_base32` — decoding stays inherent because construction needs `Self`;
- forwarding from the `fixed_newtype!` / `dynamic_newtype!` macros, so a shaped newtype gets
  `ToBase32` and `try_from_base32` like it gets the other four formats today;
- a heap-free, `Copy`, `#[non_exhaustive]`, build-invariant `Base32Error`, plus a
  `DecodingError::InvalidBase32` variant;
- the same test, fuzz, CI, and documentation coverage the base64 path has.

Everything is behind a new `encoding-base32` feature so users who do not opt in pay nothing —
not even the dependency.

## 2. Why

- **TOTP/HOTP interop is the driver.** RFC 6238 / RFC 4226 shared secrets are carried as Base32
  in `otpauth://` key URIs (uppercase, unpadded). Any project that provisions or imports
  authenticator seeds needs this exact form; several downstream projects already do, and today
  they must reach outside this crate for a non-constant-time encoder and hand-wrap the output.
- **It is the better QR export format.** `ToHex`'s own docs advertise QR export. Uppercase hex and
  Base32 both fit QR *alphanumeric* mode (denser than byte mode, which base64 forces), but Base32
  carries 5 bits per character against hex's 4: a 20-byte seed is 32 characters instead of 40.
- **`base32ct` is the sibling of what is already here.** `base16ct` and `base64ct` are both
  RustCrypto/formats crates chosen for their data-independent ("best effort" constant-time)
  encode/decode and `no_std` support. `base32ct` is the same family, same authors, same design,
  same MSRV.

## 3. Facts verified against `base32ct` 0.3.1

Everything in this section was checked by fetching the published crate source and running it
(`cargo test` in a scratch project, cross-checked against the independent `base32` 0.5 crate,
which is also what `base32ct`'s own equivalence tests use as their oracle). Nothing below is
assumed from documentation.

### 3.1 Manifest

| Property | Value | Fit with this workspace |
|---|---|---|
| Version | 0.3.1 (2026-02-26) | pre-1.0 — see §9 Risks |
| Edition / MSRV | 2024 / **1.85** | identical to `rust-version = "1.85"` |
| Features | `alloc` only; **no `std` feature** | nothing can silently leak `std` into `no_std` builds |
| Dependencies | none | no transitive surface |
| License | Apache-2.0 OR MIT | same as `base16ct` / `base64ct` |
| Attribute | `#![no_std]` unconditionally | cross-builds for `thumbv7em-none-eabihf` as-is |

### 3.2 Public API (complete)

```rust
pub use base32ct::{
    Base32, Base32Unpadded, Base32Upper, Base32UpperUnpadded, // alphabet marker types
    Encoding, encoded_len,                                     // trait + const fn
    Error, Result,                                             // Error::{InvalidEncoding, InvalidLength}
};

pub trait Encoding: Alphabet {
    fn decode(src: impl AsRef<[u8]>, dst: &mut [u8]) -> Result<&[u8]>;   // no-alloc
    #[cfg(feature = "alloc")] fn decode_vec(input: &str) -> Result<Vec<u8>>;
    fn encode<'a>(src: &[u8], dst: &'a mut [u8]) -> Result<&'a str>;     // no-alloc
    #[cfg(feature = "alloc")] fn encode_string(input: &[u8]) -> String;
    fn encoded_len(bytes: &[u8]) -> usize;
}
pub const fn encoded_len<T: Encoding>(length: usize) -> usize;
```

| Alphabet type | Characters | Padding |
|---|---|---|
| `Base32Upper` | `A–Z`, `2–7` | `=` to a multiple of 8 |
| **`Base32UpperUnpadded`** | `A–Z`, `2–7` | none — **the form this plan exposes** |
| `Base32` | `a–z`, `2–7` | `=` |
| `Base32Unpadded` | `a–z`, `2–7` | none |

Not provided: base32hex (`0–9A–V`), Crockford, z-base-32, or any case-insensitive ("mixed")
decoder. Unlike `base16ct::mixed`, **each `base32ct` alphabet decodes only its own case**.

### 3.3 Encode vectors (`Base32UpperUnpadded` / `Base32Upper`)

RFC 4648 §10 vectors plus the values the existing base64 tests use, all reproduced exactly:

| Input | Unpadded (what we emit) | Padded (RFC 4648 §10) |
|---|---|---|
| `""` | `""` | `""` |
| `"f"` | `MY` | `MY======` |
| `"fo"` | `MZXQ` | `MZXQ====` |
| `"foo"` | `MZXW6` | `MZXW6===` |
| `"foob"` | `MZXW6YQ` | `MZXW6YQ=` |
| `"fooba"` | `MZXW6YTB` | `MZXW6YTB` |
| `"foobar"` | `MZXW6YTBOI` | `MZXW6YTBOI======` |
| `"hello"` | `NBSWY3DP` | `NBSWY3DP` |
| `[0xDE, 0xAD, 0xBE, 0xEF]` | `32W353Y` | `32W353Y=` |
| `[0x42; 4]` | `IJBEEQQ` | `IJBEEQQ=` |
| `[0xAB; 4]` (the wrapper doctest vector since #156) | `VOV2XKY` | `VOV2XKY=` |
| `[0x00; 1]` | `AA` | `AA======` |
| `[0x00; 3]` | `AAAAA` | `AAAAA===` |
| `[0x07; 32]` | `A4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQ` (52 chars) | `…A4DQ====` |
| `[0xAA; 20]` (TOTP seed size) | `VKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVK` (32 chars) | same (20 ≡ 0 mod 5) |

Encoded lengths for comparison: 16 bytes → 26 chars; 20 bytes → 32 chars (hex 40,
base64url 27); 32 bytes → 52 chars (hex 64, base64url 43).
`encoded_len::<Base32UpperUnpadded>(n)` is a `const fn` if a stack buffer size is ever needed.

### 3.4 Decode behaviour (`Base32UpperUnpadded::decode_vec`)

| Input | Result | Note |
|---|---|---|
| `""` | `Ok([])` | empty is valid |
| `"NBSWY3DP"` | `Ok(b"hello")` | |
| `"nbswy3dp"` | `Err(InvalidEncoding)` | **lowercase rejected** |
| `"NbSwY3Dp"` | `Err(InvalidEncoding)` | mixed case rejected |
| `"MY======"` | `Err(InvalidEncoding)` | **padding rejected** |
| `"="` | `Err(InvalidEncoding)` | |
| `"!!!!"`, `"0189"` | `Err(InvalidEncoding)` | `0 1 8 9` are not in the alphabet |
| `"M"`, `"MZX"`, `"MZXW6Y"` | `Err(InvalidEncoding)` | length ≡ 1, 3, 6 (mod 8) is impossible for unpadded Base32 |
| `"MY"`, `"MZXQ"`, `"MZXW6"`, `"MZXW6YQ"` | `Ok` | length ≡ 2, 4, 5, 7 (mod 8) — the legal partial groups |
| `"MZ"` | `Ok([0x66])` | **non-canonical trailing bits accepted** — decodes the same as `"MY"` |
| `"NBSW Y3DP"` | `Err(InvalidEncoding)` | whitespace rejected |
| `"NBSWY3DPé"` | `Err(InvalidEncoding)` | non-ASCII rejected |

No-alloc path, `Base32UpperUnpadded::decode(src, dst)`:

| Call | Result |
|---|---|
| `decode("NBSWY3DP", &mut [u8; 5])` | `Ok(b"hello")` |
| `decode("NBSWY3DP", &mut [u8; 4])` | `Err(InvalidLength)` — buffer too small |
| `decode("NBSWY3DP", &mut [u8; 32])` | `Ok(&[..5])` — over-sized buffer is fine, slice is exact |
| `decode("32W353Y", &mut [u8; 4])` | `Ok([0xDE, 0xAD, 0xBE, 0xEF])` |

The padded alphabet is **not** a superset: `Base32Upper::decode_vec("MY")` fails (length not a
multiple of 8) while `"MY======"` succeeds. The two alphabets are mutually exclusive on decode;
anything that accepts both has to dispatch (see D2).

### 3.5 Constant-time claim

Same wording `base16ct` and `base64ct` carry: no data-dependent branches or lookup tables, so
"best effort" constant-time with respect to the *data*; **not** constant-time with respect to
length. Existing crate docs already describe the hex and base64 backends as "constant-time";
the base32 docs should use the identical phrasing and the identical caveat.

## 4. Design decisions

### D1 — One canonical form: uppercase, unpadded (`Base32UpperUnpadded`)

RFC 4648 §6 defines the alphabet in uppercase; the `otpauth://` Key URI convention is uppercase
without padding. This is the form every TOTP/HOTP consumer emits and expects, and it is the form
that fits QR alphanumeric mode. Encoding emits it; decoding accepts only it.

*Rejected alternative:* also offering `to_base32_lower()` like `to_hex_upper()`. Hex can do that
because `base16ct::mixed` decodes either case, so the encode variants round-trip through the one
decoder. `base32ct` has no mixed decoder, so a lowercase encoder would produce strings that
`try_from_base32` rejects — an asymmetry that also breaks the fuzz round-trip invariant. If
lowercase is ever wanted, add it in **both** directions at once (`to_base32_lower` +
`try_from_base32_lower`, backed by `Base32Unpadded`). Recorded in §8.

### D2 — Strict decode: reject padding and lowercase

Mirrors `FromBase64UrlStr`, which is strict single-form (URL-safe, unpadded) and has an explicit
`rejects_padding` test. Strict means: smallest surface, one pass, no dispatch on input shape,
no second decode attempt.

*Cheap relaxations, if demand appears (both documented in §8):*

- **Accept trailing `=`:** `s.trim_end_matches('=')` is a zero-copy sub-slice (no unzeroized
  temporary) and the number of `=` is derivable from the length, so it is not secret. Feed the
  trimmed slice to the unpadded decoder. Would need the `rejects_padding` test inverted.
- **Accept lowercase:** dispatch on the first alphabetic character (or try `Upper` then `Lower`).
  The branch leaks only which case the *encoding* used, never data bits — but it is a second
  code path to audit. Prefer explicit `_lower` methods over silent tolerance.

Callers who receive lowercase from a third party can `s.to_ascii_uppercase()` before decoding;
document that this makes an ordinary `String` copy of the encoded secret (wrap it in
`zeroize::Zeroizing<String>` if that matters).

### D3 — Naming and placement

| Item | Name / shape | Precedent |
|---|---|---|
| Feature | `encoding-base32` | `encoding-base64` |
| Encode trait / methods | `ToBase32` — `to_base32()`, `to_base32_zeroizing()` | `ToBase64Url` |
| Decode trait / method | `FromBase32Str` — `try_from_base32()` | `FromBase64UrlStr` |
| Wrapper encoders | `impl ToBase32 for Fixed<[u8; N]>` and `for Dynamic<Vec<u8>>`, delegating via `with_secret`; **not** inherent (#156) | `impl ToBase64Url for …` |
| Wrapper decoders | inherent `Fixed::try_from_base32`, `Dynamic::try_from_base32` | `try_from_base64url` |
| Newtype forwarding | `__sg_if_base32!` helper; `impl ToBase32 for $name` + inherent `try_from_base32` in both front-end macros | `__sg_if_base64!` |
| Error | `Base32Error::{InvalidBase32, InvalidLength { expected, got }}` | `Base64Error` |
| Unified error variant | `DecodingError::InvalidBase32(#[source] Base32Error)` | `InvalidBase64` |
| Modules | `traits/encoding/base32.rs`, `traits/decoding/base32.rs` | `base64_url.rs` |

No "url"/"upper" qualifier in the name: there is one form (D1), and a qualifier would invite a
second. If D1 is ever relaxed, the *new* variants get the qualifier.

Call sites need `use secure_gate::ToBase32;` to call `key.to_base32()` on a wrapper — the same
import rule the other four formats acquired in #156.

### D4 — Error mapping mirrors base64 exactly

Every `base32ct::Error` on the decode path maps to `Base32Error::InvalidBase32`; a decoded length
≠ `N` maps to `Base32Error::InvalidLength { expected: N, got }`. On the no-alloc path a
too-long input surfaces as `base32ct::Error::InvalidLength` (buffer too small) and is therefore
reported as `InvalidBase32`, exactly as `try_from_base64url` does today.

*Known wrinkle (pre-existing in base64, not introduced here):* the alloc and no-alloc paths thus
report a too-long input differently (`InvalidLength` vs `InvalidBase32`). Both are errors and the
existing tests only assert `is_err()`. Fixing it for all formats at once is a §8 follow-up; do not
diverge from the base64 shape in this change.

### D5 — Non-canonical trailing bits are accepted (documented, not fixed)

`"MZ"` decodes to the same byte as `"MY"`. This is `base32ct` behaviour (and the RFC permits
lenient decoders). Consequences:

- `decode(encode(x)) == x` always holds (the encoder is canonical).
- `encode(decode(s)) == s` holds only for canonical `s`. The fuzz target's "stable re-encoding"
  check must feed *encoder-generated* strings, which is what the existing hex/base64 sections
  already do via `FuzzHexString` / `FuzzBase64String`. Keep that pattern.
- Add one test that pins the behaviour so a future `base32ct` change is noticed.

### D6 — Zeroization discipline is the base64 discipline

- `Fixed::try_from_base32` (alloc): `Zeroizing<Vec<u8>>` from `decode_vec`, length check, copy
  into `new_with`. (no-alloc): `Zeroizing<[u8; N]>` stack buffer, `decode` into it, length check.
- `Dynamic::try_from_base32`: `from_protected_bytes(Zeroizing::new(s.try_from_base32()?))`, so the
  buffer is zeroized even if the `Box` allocation panics.
- `to_base32_zeroizing` wraps in `EncodedSecret` via `EncodedSecret::new`, whose `cfg(any(...))`
  list must gain the new feature.

## 5. Phases

Each phase leaves the tree compiling and green. Line numbers refer to `0.9.0-rc.8`
(`6ebd15c`) and are there to make the touch points easy to find, not as targets to preserve.

### Phase 0 — Dependency and features (`secure-gate-core/Cargo.toml`, `Cargo.lock`)

```toml
[dependencies]
base16ct = { version = "1", optional = true, default-features = false }
base32ct = { version = "0.3", optional = true, default-features = false }   # new
base64ct = { version = "1", optional = true, default-features = false }

[features]
alloc = [
    "zeroize/alloc",
    "base16ct?/alloc",
    "base32ct?/alloc",          # new
    "base64ct?/alloc",
    "bech32?/alloc",
]

encoding = [
  "encoding-hex",
  "encoding-base32",            # new
  "encoding-base64",
  "encoding-bech32",
  "encoding-bech32m",
]
encoding-hex = ["dep:base16ct"]
encoding-base32 = ["dep:base32ct"]   # new
encoding-base64 = ["dep:base64ct"]
```

- `default-features = false` is a no-op for `base32ct` (it has no default features) but keeps
  the three `*ct` lines uniform.
- `full` already includes `encoding`; no change. The `--all-features` CI entries added in rc.8
  pick the feature up automatically.
- Regenerate `Cargo.lock` with the pinned toolchain (`cargo update -p base32ct` or a plain
  build). The workspace `.cargo/config.toml` MSRV-aware resolver will refuse a future
  `base32ct` release whose `rust-version` exceeds 1.85.
- `secure-gate-compat` forwards no encoding features; nothing to do there.

### Phase 1 — Error types (`src/error.rs`, unchanged by rc.8)

- Add `Base32Error` between `Bech32Error` and `Base64Error`, a copy of `Base64Error` with the
  names swapped:

  ```rust
  /// Errors produced when decoding Base32 (RFC 4648 §6, uppercase, unpadded) strings.
  ///
  /// *Requires feature `encoding-base32`.*
  ///
  /// Variant shapes are identical in debug and release builds; only numeric
  /// length metadata is carried.
  #[cfg(feature = "encoding-base32")]
  #[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
  #[non_exhaustive]
  pub enum Base32Error {
      /// The string is not valid Base32 (wrong alphabet, wrong case, padding, or impossible length).
      #[error("invalid base32 string")]
      InvalidBase32,
      /// The decoded payload length does not match the target type's length.
      #[error("decoded length mismatch: expected {expected}, got {got}")]
      #[non_exhaustive]
      InvalidLength {
          /// Number of bytes the target type requires.
          expected: usize,
          /// Number of bytes actually decoded.
          got: usize,
      },
  }
  ```

- Add to `DecodingError`:

  ```rust
  /// The input is not valid Base32.
  #[cfg(feature = "encoding-base32")]
  #[error("invalid base32 string")]
  InvalidBase32(#[source] Base32Error),
  ```

- Extend the module-level error table (lines 5–11) with a `Base32Error` row and mention base32
  in the `DecodingError` doc comment ("Wraps format-specific errors from hex, base32, base64url,
  bech32, and bech32m decoders").

### Phase 2 — Traits

**`src/traits/encoding/base32.rs` (new)** — mirror `base64_url.rs` as it reads after #156:

```rust
//! Base32 encoding trait (RFC 4648 §6, uppercase, unpadded).
//!
//! > **Import path:** `use secure_gate::ToBase32;`
//!
//! This trait provides secure, explicit encoding of byte data to Base32 strings using the
//! RFC 4648 §6 alphabet (`A–Z`, `2–7`), uppercase, without `=` padding — the form used for
//! TOTP/HOTP shared secrets in `otpauth://` key URIs (RFC 6238 / RFC 4226) and the densest
//! form that fits QR alphanumeric mode. Intended for intentional export only.
//!
//! Requires the `encoding-base32` feature.
//!
//! # Security Notes
//!
//! - **Full secret exposure**, **Zeroizing variants**, **Explicit exposure**: same three
//!   paragraphs as `base64_url.rs`, with names substituted.
//! - **Canonical form only**: uppercase, unpadded. See [`FromBase32Str`] for what the
//!   decoder accepts.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-base32")]
//! use secure_gate::{Fixed, ToBase32, RevealSecret};
//! # #[cfg(feature = "encoding-base32")]
//! {
//! let secret = Fixed::new([0x42u8; 4]);
//! let b32 = secret.with_secret(|s| s.to_base32());
//! assert_eq!(b32, "IJBEEQQ");
//! assert_eq!(secret.to_base32(), "IJBEEQQ");   // wrapper impl of the same trait
//! let b32z = secret.to_base32_zeroizing();     // EncodedSecret — zeroized on drop, redacted Debug
//! }
//! ```
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
use base32ct::{Base32UpperUnpadded, Encoding};

/// Extension trait for encoding byte data as Base32 strings (RFC 4648 §6, uppercase, unpadded).
///
/// *Requires feature `encoding-base32`.*
///
/// Blanket-implemented for all `AsRef<[u8]>` types, and implemented directly on the
/// byte-shaped wrappers (`Fixed<[u8; N]>`, `Dynamic<Vec<u8>>`). To encode a secret wrapper,
/// call `key.to_base32()` with this trait in scope, or use `with_secret(|b| b.to_base32())`
/// for multi-step operations or when audit-greppability matters.
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
pub trait ToBase32 {
    /// Encode bytes as Base32 (RFC 4648 §6 alphabet, uppercase, no padding).
    fn to_base32(&self) -> alloc::string::String;
    /// Encode bytes as Base32 and wrap the result in [`crate::EncodedSecret`].
    fn to_base32_zeroizing(&self) -> crate::EncodedSecret;
}

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
impl<T: AsRef<[u8]> + ?Sized> ToBase32 for T {
    #[inline(always)]
    fn to_base32(&self) -> alloc::string::String {
        Base32UpperUnpadded::encode_string(self.as_ref())
    }
    #[inline(always)]
    fn to_base32_zeroizing(&self) -> crate::EncodedSecret {
        crate::EncodedSecret::new(self.to_base32())
    }
}
```

There is no coherence conflict between this blanket impl and the wrapper impls in Phase 3:
`Fixed` and `Dynamic` are local and deliberately never implement `AsRef<[u8]>` (the #156
argument, unchanged).

**`src/traits/decoding/base32.rs` (new)** — mirror `decoding/base64_url.rs`:

```rust
//! Base32 decoding trait (RFC 4648 §6, uppercase, unpadded).
//!
//! > **Import path:** `use secure_gate::FromBase32Str;`
//!
//! Requires the `encoding-base32` feature.
//!
//! # Security Notes
//!
//! - **Treat all input as untrusted** / **Heap allocation**: as `base64_url.rs`.
//! - **Strict validation**: uppercase RFC 4648 §6 alphabet only, no `=` padding, no
//!   whitespace, length must be ≡ 0, 2, 4, 5 or 7 (mod 8). Lowercase input is rejected;
//!   normalise upstream (`to_ascii_uppercase()`, ideally inside `zeroize::Zeroizing`).
//! - **Lenient trailing bits**: non-zero bits in the final partial group are ignored rather
//!   than rejected (`"MZ"` decodes like `"MY"`). Only encoder-produced strings are canonical.
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
use crate::error::Base32Error;

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
pub trait FromBase32Str {
    /// Decodes an uppercase, unpadded Base32 string into a byte vector.
    ///
    /// # Errors
    ///
    /// - [`Base32Error::InvalidBase32`] — wrong alphabet or case, padding, whitespace, or an
    ///   impossible length.
    ///
    /// ```rust
    /// use secure_gate::FromBase32Str;
    /// assert_eq!("NBSWY3DP".try_from_base32()?, b"hello");
    /// assert!("nbswy3dp".try_from_base32().is_err()); // lowercase
    /// assert!("MY======".try_from_base32().is_err()); // padding
    /// # Ok::<(), secure_gate::Base32Error>(())
    /// ```
    fn try_from_base32(&self) -> Result<alloc::vec::Vec<u8>, Base32Error>;
}

#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
impl<T: AsRef<str> + ?Sized> FromBase32Str for T {
    fn try_from_base32(&self) -> Result<alloc::vec::Vec<u8>, Base32Error> {
        use base32ct::{Base32UpperUnpadded, Encoding};
        Base32UpperUnpadded::decode_vec(self.as_ref()).map_err(|_| Base32Error::InvalidBase32)
    }
}
```

**Wiring:**

- `src/traits/encoding/mod.rs`: `pub mod base32;`, `pub use base32::ToBase32;` under
  `cfg(all(feature = "encoding-base32", feature = "alloc"))`, table row.
- `src/traits/decoding/mod.rs`: same for `FromBase32Str`; also add `Fixed::try_from_base32` to
  the "no-alloc targets" sentence.
- `src/traits/mod.rs`: re-exports (lines 73–100); add `encoding-base32` to **all four**
  `cfg(any(...))` lists on `SecureEncoding` / `SecureDecoding` and their impls (lines 112–152);
  update the doc table rows for those two markers (lines 23–24).

  > **\[Superseded]** This step was performed as written when Base32 landed, then reverted:
  > `SecureEncoding` and `SecureDecoding` were **removed from the crate** later in
  > 0.9.0-rc.8. They were empty marker traits with blanket impls over `AsRef<[u8]>` /
  > `AsRef<str>`, and nothing — including the per-format encoding traits this plan adds —
  > ever bounded on them. A future format needs no marker wiring: there are no `cfg(any(...))`
  > lists and no doc-table rows left to update. Only the re-export half of this bullet
  > (lines 73–100) still applies.
- `src/traits/revealed_secrets/encoded_secret.rs`: add the feature to the `cfg(any(...))` on
  `EncodedSecret::new` (lines 59–64). Mention `to_base32_zeroizing` in the module docs of
  `encoded_secret.rs` (line 7) and `revealed_secrets/mod.rs` (line 10).

### Phase 3 — Wrapper impls (`src/fixed.rs`, `src/dynamic.rs`)

Since #156 the wrappers carry **two** things per format: an inherent decode constructor and a
trait impl for the encoder. Both are copied from the base64 twins with names swapped.

**`src/fixed.rs`**

- Import next to the others (lines 94–95):
  `#[cfg(all(feature = "encoding-base32", feature = "alloc"))] use crate::traits::encoding::base32::ToBase32;`
- Constructor table (line 167): `| [`try_from_base32`](Self::try_from_base32) | `encoding-base32` | Constant-time Base32 decoding |`
- **Inherent decode constructor**, a copy of the base64 block at lines 397–470 placed directly
  after it. Doctest vector: `[0xDE, 0xAD, 0xBE, 0xEF]` ↔ `"32W353Y"`, with
  `use secure_gate::{Fixed, RevealSecret, ToBase32};` in the doctest (the round-trip calls the
  wrapper's `to_base32`, which needs the trait in scope).

  ```rust
  /// Base32 decoding for `Fixed<[u8; N]>` (RFC 4648 §6, uppercase, unpadded).
  ///
  /// Uses a constant-time backend (`base32ct`). Works with or without the `alloc`
  /// feature — on no-alloc targets the bytes are decoded directly into a
  /// `Zeroizing<[u8; N]>` stack buffer. Encoding lives on the [`ToBase32`] impl.
  #[cfg(feature = "encoding-base32")]
  impl<const N: usize> Fixed<[u8; N]> {
      /// # Errors
      ///
      /// - [`Base32Error::InvalidBase32`] — wrong alphabet or case, padding, or impossible length.
      /// - [`Base32Error::InvalidLength`] — decoded byte count does not equal `N`.
      pub fn try_from_base32(s: &str) -> Result<Self, crate::error::Base32Error> {
          #[cfg(feature = "alloc")]
          {
              use base32ct::{Base32UpperUnpadded, Encoding};
              use zeroize::Zeroizing;
              let bytes = Zeroizing::new(
                  Base32UpperUnpadded::decode_vec(s)
                      .map_err(|_| crate::error::Base32Error::InvalidBase32)?,
              );
              if bytes.len() != N {
                  return Err(crate::error::Base32Error::InvalidLength { expected: N, got: bytes.len() });
              }
              Ok(Self::new_with(|arr| arr.copy_from_slice(&bytes)))
          }
          #[cfg(not(feature = "alloc"))]
          {
              use base32ct::{Base32UpperUnpadded, Encoding};
              use zeroize::Zeroizing;
              let mut buf = Zeroizing::new([0u8; N]);
              let decoded = Base32UpperUnpadded::decode(s, &mut *buf)
                  .map_err(|_| crate::error::Base32Error::InvalidBase32)?;
              if decoded.len() != N {
                  return Err(crate::error::Base32Error::InvalidLength { expected: N, got: decoded.len() });
              }
              Ok(Self::new_with(|arr| arr.copy_from_slice(decoded)))
              // buf is zeroized on drop (both success and error paths)
          }
      }
  }
  ```

- **Encoder trait impl**, a copy of the `ToBase64Url` impl at lines 606–627 placed directly
  after it (doctest: `Fixed::new([0xABu8; 4]).to_base32() == "VOV2XKY"`):

  ```rust
  /// Base32 encoding for `Fixed<[u8; N]>`; delegates via `with_secret`.
  ///
  /// Bring the trait into scope to call these: `use secure_gate::ToBase32;`.
  #[cfg(all(feature = "encoding-base32", feature = "alloc"))]
  impl<const N: usize> ToBase32 for Fixed<[u8; N]> {
      #[inline]
      fn to_base32(&self) -> alloc::string::String {
          self.with_secret(|s| s.to_base32())
      }

      #[inline]
      fn to_base32_zeroizing(&self) -> crate::EncodedSecret {
          self.with_secret(|s| s.to_base32_zeroizing())
      }
  }
  ```

**`src/dynamic.rs`**

- Add `feature = "encoding-base32"` to the `cfg(any(...))` that imports `RevealSecret`
  (lines 102–109).
- Imports: `ToBase32` next to line 113, `FromBase32Str` next to line 127 (both gated on
  `encoding-base32` only — `Dynamic` is always `alloc`).
- Constructor table (line 166): `| [`try_from_base32(s)`](Self::try_from_base32) | `encoding-base32` | Constant-time Base32 decoding |`
- Inherent decode constructor after the base64 one (lines 253–265):

  ```rust
  // Base32 decoding for Dynamic<Vec<u8>>. Encoding lives on the ToBase32 impl below.
  #[cfg(feature = "encoding-base32")]
  impl Dynamic<Vec<u8>> {
      /// Decodes an uppercase, unpadded Base32 string into `Dynamic<Vec<u8>>`.
      ///
      /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
      /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
      pub fn try_from_base32(s: &str) -> Result<Self, crate::error::Base32Error> {
          Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(s.try_from_base32()?)))
      }
  }
  ```

- Encoder trait impl after the `ToBase64Url` one (lines 430–453):

  ```rust
  /// Base32 encoding for `Dynamic<Vec<u8>>`; delegates via `with_secret`.
  ///
  /// Bring the trait into scope: `use secure_gate::ToBase32;`.
  #[cfg(feature = "encoding-base32")]
  impl ToBase32 for Dynamic<Vec<u8>> {
      #[inline]
      fn to_base32(&self) -> alloc::string::String {
          self.with_secret(|s| s.to_base32())
      }

      #[inline]
      fn to_base32_zeroizing(&self) -> crate::EncodedSecret {
          self.with_secret(|s| s.to_base32_zeroizing())
      }
  }
  ```

`Dynamic<String>` gets nothing, as with the other formats. The existing compile-fail probe
`tests/compile-fail/dynamic_string_no_hex.rs` (which now imports `ToHex` and proves the impl
genuinely does not exist) already pins that property generically; a base32 twin would only add
a `.stderr` to bless. Leave it.

### Phase 3b — Newtype macro forwarding (`src/macros/`)

Shaped newtypes (`fixed_newtype!(Name, N)`, `dynamic_newtype!(Name, Vec<u8>)`) forward every
encoding format; the `String` and `generic` arms deliberately forward none. Base32 joins the
list the same way base64 is in it.

- `src/macros/newtype_common.rs`: add a `__sg_if_base32!` pair beside `__sg_if_base64!`
  (lines 322–331):

  ```rust
  #[doc(hidden)]
  #[macro_export]
  #[cfg(feature = "encoding-base32")]
  macro_rules! __sg_if_base32 { ($($t:tt)*) => { $($t)* }; }
  #[doc(hidden)]
  #[macro_export]
  #[cfg(not(feature = "encoding-base32"))]
  macro_rules! __sg_if_base32 {
      ($($t:tt)*) => {};
  }
  ```

- `src/macros/fixed_newtype.rs`: a block after the base64 one (lines 269–289). The decode
  constructor is outside `__sg_if_alloc!` (it works no-alloc); the encoder impl is inside it:

  ```rust
  $crate::__sg_if_base32! {
      impl $name {
          /// Constant-time Base32 decode into this secret type.
          #[inline]
          pub fn try_from_base32(s: &str) -> ::core::result::Result<Self, $crate::Base32Error> {
              ::core::result::Result::Ok(Self($crate::Fixed::try_from_base32(s)?))
          }
      }
      $crate::__sg_if_alloc! {
          impl $crate::ToBase32 for $name {
              #[inline]
              fn to_base32(&self) -> $crate::__private::String {
                  $crate::ToBase32::to_base32(&self.0)
              }
              #[inline]
              fn to_base32_zeroizing(&self) -> $crate::EncodedSecret {
                  $crate::ToBase32::to_base32_zeroizing(&self.0)
              }
          }
      }
  }
  ```

- `src/macros/dynamic_newtype.rs`: same block after lines 275–295, without the `__sg_if_alloc!`
  layer and delegating to `<$crate::Dynamic<$crate::__private::Vec<u8>>>::try_from_base32`.
- Macro rustdoc: wherever the front-end macros enumerate the forwarded encoders (search the
  three macro files and `src/macros/mod.rs` for `ToBech32m`), add `ToBase32` /
  `try_from_base32`. `secure-gate-core/docs/composability_restructure.md` line 185 and
  `docs/nominal_newtypes.md` list the four traits as a historical record; a one-word update is
  fine but not required.
- `tests/macros_suite/newtype_surface.rs`: import `ToBase32`; in `fixed_full_surface` and
  `dynamic_vec_full_surface` add the base32 round trip beside the base64 one
  (`let b32 = h.to_base32(); assert_eq!(EncKey::try_from_base32(&b32).unwrap().to_hex(), h.to_hex());`
  — rename the existing bech32 local `b32` to avoid the clash) and a
  `to_base32_zeroizing().len()` line beside line 41.
- `tests/newtype_nostd.rs` (optional): a `#[cfg(feature = "encoding-base32")]` assertion that
  `NoStdKey::try_from_base32` is callable, pinning the no-alloc forwarding path.

### Phase 4 — Crate root (`src/lib.rs`)

- Module tree comment (lines 91–94): add `ToBase32`, `FromBase32Str`, `Base32Error`.
- Audit-sweep paragraph (line 157) lists the encoder traits — add `ToBase32`.
- Feature table (after line 179):
  `| `encoding-base32` | no | [`ToBase32`] / [`FromBase32Str`] via `base32ct` (constant-time) |`
- "What's available without `alloc`" (≈ line 191): add `Fixed::try_from_base32`.
- Re-exports, alphabetical with the existing ones (lines 477–519), each with the same
  two-line doc style:
  `pub use traits::FromBase32Str;` / `pub use traits::ToBase32;` under
  `cfg(all(feature = "encoding-base32", feature = "alloc"))`, and
  `pub use error::Base32Error;` under `cfg(feature = "encoding-base32")`.
- Add the feature to both `cfg(any(...))` lists on the `SecureDecoding` / `SecureEncoding`
  re-exports (lines 522–539); mention `Base32Error` in the `DecodingError` doc (line 558).

  > **\[Superseded]** The marker re-exports are gone — see the note in Phase 2. The
  > `DecodingError` doc half of this bullet still applies.

### Phase 5 — Tests

**`tests/encoding_suite/base32.rs` (new) + `mod base32;` in `encoding_suite/mod.rs`.**
Mirror `base64.rs` test-for-test with the §3.3/§3.4 vectors, then add the base32-specific
cases. Imports mirror the base64 file's post-#156 form
(`use secure_gate::{Fixed, FromBase32Str, RevealSecret, ToBase32};` — the trait import is
what makes `secret.to_base32()` resolve). Every test carries the same `cfg` gates as its
base64 twin.

| Test | Asserts |
|---|---|
| `test_slice_to_base32` | `b"hello"` round-trips through the traits |
| `slice_to_base32_zeroizing` | `b"hello".to_base32_zeroizing()` derefs to `"NBSWY3DP"` |
| `fixed_to_base32_zeroizing_matches_plain` / `dynamic_…` | `[7u8; 32]` and `vec![10, 20, 30]` |
| `fixed_to_base32_zeroizing_debug_is_redacted` | `"[REDACTED]"` |
| `fixed_to_base32_zeroizing_empty` | `""` |
| `fixed_to_base32_zeroizing_all_zeros` | `[0u8; 3]` → `"AAAAA"` |
| `fixed_try_from_base32_roundtrip` / `dynamic_…` | `[7u8; 32]`, `vec![10, 20, 30]` |
| `dynamic_try_from_base32_invalid_input_returns_err` | `"not valid base32!!!"` |
| `fixed_try_from_base32_wrong_length_too_long` | `"NBSWY3DP"` (5 bytes) into `[u8; 4]` |
| `fixed_try_from_base32_wrong_length_too_short` | `"MZXQ"` (2 bytes) into `[u8; 4]` |
| `fixed_try_from_base32_invalid_chars` | `"!!!!"` and `"0189"` |
| `fixed_try_from_base32_all_zeros` | `"AAAAA"` → `[0u8; 3]` |
| `fixed_try_from_base32_empty_input` | `""` into `[u8; 4]` is `Err` |
| `fixed_try_from_base32_zero_size` | `Fixed::<[u8; 0]>::try_from_base32("")` is `Ok` |
| `fixed_try_from_base32_single_byte` | `"AA"` → `[0u8]` |
| `fixed_try_from_base32_rejects_lowercase` | `"nbswy3dp"`, `"NbSwY3Dp"` |
| `fixed_try_from_base32_rejects_padding` | `"MY======"` into `[u8; 1]`, `"MZXQ===="` into `[u8; 2]` |
| `fixed_try_from_base32_rejects_impossible_lengths` | `"M"`, `"MZX"`, `"MZXW6Y"` |
| `fixed_try_from_base32_rejects_whitespace` | `"NBSW Y3DP"` |
| `base32_rfc4648_section_10_vectors` | the six §10 vectors, both directions, via `Dynamic` |
| `base32_accepts_non_canonical_trailing_bits` | `"MZ".try_from_base32() == Ok(vec![0x66])` (pins D5) |
| `fixed_try_from_base32_totp_seed_size` | `[0xAAu8; 20]` → 32 chars → back |
| `fixed_try_from_base32_large_n` | `[0x42u8; 128]` |
| `to_base32_is_generic_over_wrappers` | `fn export<S: ToBase32>(s: &S) -> String` accepts a `Fixed`, a `Dynamic`, and a `fixed_newtype!` (pins the #156 property for the new trait) |

**`tests/proptest_suite/encoding.rs`:** add a `b32_roundtrip` module identical to
`b64_roundtrip` (256 cases, same length distribution, `use secure_gate::{Dynamic, RevealSecret, ToBase32}`)
using `to_base32` / `Dynamic::try_from_base32`.

**`tests/error_tests.rs`:**

- Add `encoding-base32` to the two `cfg(any(...))` lists (lines 16–20, 90–94).
- `base32_error_invalid_length`: `Fixed::<[u8; 2]>::try_from_base32("32W353Y")` →
  `InvalidLength { expected: 2, got: 4 }`, Display `"decoded length mismatch: expected 2, got 4"`.
- `decoding_error_source_base32`: `DecodingError::InvalidBase32(Base32Error::InvalidBase32)`
  has a `source()` whose Display contains `"invalid base32"`.

**`tests/heap_zeroize.rs`:** add `check_decode_base32_zeroed(data: &[u8])` next to the base64
one (lines 316–334, same `shrink_to_fit` + proxy-window pattern; it encodes a plain slice via
the blanket impl) and call it with `[0xAAu8; 16]` and `[0xBBu8; 32]` beside the base64 calls
(line 632). Update the comment at line 294 ("hex, base32, base64url, bech32, bech32m").

**Compile-fail naming:** CI now skips compile-fail tests by the `_compile_fail` name suffix.
None are planned here, but any that is added must follow that suffix.

### Phase 6 — Fuzz (`secure-gate-core/fuzz/`)

- `Cargo.toml`: `encoding-base32 = ["secure-gate/encoding-base32"]` in `[features]`; add the
  independent oracle `base32 = "0.5"` under "Direct deps for encoding round-trip verification"
  (the same crate `base32ct`'s own equivalence tests use). The `encoding` meta already
  forwards the new feature, so the default feature set picks it up.
- `src/arbitrary.rs`: `FuzzBase32String(pub String)` generated as
  `base32::encode(base32::Alphabet::Rfc4648 { padding: false }, capped)` (cap 512 bytes like
  the others). Because the oracle produces canonical uppercase unpadded strings, the
  "stable re-encoding" check below is valid (D5).
- `fuzz_targets/encoding.rs`: import `ToBase32`; a `=== BASE32 ===` section between base64 and
  bech32 with the four sub-blocks the base64 section has: (a) arbitrary strings into
  `Fixed::<[u8; 32]>::try_from_base32` and `Dynamic::<Vec<u8>>::try_from_base32` must never
  panic; (b) `FuzzBase32String` → decode → `to_base32` equals the input; (c)
  `FuzzFixed16` round-trip (16 bytes ↔ 26 chars); (d) edge cases `""`, `"MY======"`,
  `"nbswy3dp"`, `"AAAAA"`, `"M"`, `"MZ"`. Update the header comment and corpus seed hints
  (`"NBSWY3DP"`).
- `.github/workflows/fuzz-nightly-0.9-core.yml`: add `printf 'NBSWY3DP' > "$dir/seed_base32"`
  to the encoding-seed block. That block is currently duplicated (lines ~101–115); either add
  to both copies or take the opportunity to delete the duplicate. `fuzz-nightly-0.8-core.yml`
  targets the 0.8 branch — leave it.

### Phase 7 — CI and local matrix

- `.github/workflows/ci.yml` `test` matrix, after `encoding-base64 only` (lines 132–133):

  ```yaml
          - name: encoding-base32 only
            features: "--no-default-features --features=alloc,encoding-base32"
  ```

- `.github/workflows/ci.yml` `no-std` job feature list (lines 259–265): add
  `"encoding-base32" \` and extend both combined lines to
  `"encoding-hex,encoding-base32,encoding-base64,encoding-bech32,encoding-bech32m"` (and the
  `ct-eq,…` twin). This is the only job that compiles the no-alloc `try_from_base32` path,
  including the `fixed_newtype!` forwarding of it.
- `lint`, `test`, `test-release`, `msrv`, `compile-fail` run with `full` or `--all-features`
  and pick the feature up automatically.
- `secure-gate-core/test_all.sh`: add
  `run_tests "encoding-base32 only" "--no-default-features --features=encoding-base32"`
  beside the base64 line. (The script's encoding entries predate CI's `alloc,` prefix; follow
  whichever convention is current when landing this.)

### Phase 8 — Documentation

- **`secure-gate-core/README.md`** (rc.8 line numbers): line 159 (feature bullet), line 185
  ("four formats" → "five formats: hex, base32, base64url, bech32, bech32m"), trait table
  (191–194), the encode/zeroizing/scoped examples (204–225: add `to_base32` lines and note the
  trait import), the sentence at 228, decode constructor table (237: `| Base32 |
  `try_from_base32(s)` | `Base32Error` (RFC 4648 §6, uppercase, unpadded) |`), method lists at
  318–319, feature table (353–357). One sentence on TOTP/`otpauth://` under the format table
  earns its place; keep it to one. The newtype paragraph (≈ line 119) says generated newtypes
  carry "every wrapper guarantee"; no change needed there.
- **`secure-gate-core/SECURITY.md`** (unchanged by rc.8): line 23 (zeroizing variants list),
  line 116 (dependency list: `base32ct` — constant-time Base32 encoding/decoding (RustCrypto)),
  feature table rows 208–210, method lists at 231, 249, 379, the grep list at 391–392
  (`to_base32`, `to_base32_zeroizing`), and the two-flavour table at 418–423.
- **`secure-gate-core/CHANGELOG.md`** — `[Unreleased]` is empty above `[0.9.0-rc.8]`; add
  `### Added`:

  > **Base32 encoding (`encoding-base32`, #158).** `ToBase32` / `FromBase32Str`, `ToBase32`
  > impls on `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>`, inherent `try_from_base32` on both, and
  > `Base32Error`; `fixed_newtype!` / `dynamic_newtype!` forward all of it for byte-shaped
  > newtypes. RFC 4648 §6 alphabet, uppercase, unpadded — the `otpauth://` TOTP/HOTP form —
  > via the constant-time `base32ct` crate. Strict decoding: lowercase and `=` padding are
  > rejected. Included in the `encoding` and `full` meta-features; `Fixed::try_from_base32`
  > works without `alloc`.

- **Root `CHANGELOG.md`** `[Unreleased]`: one pointer line to the core entry, as the existing
  entries do.

### Phase 9 — Verification before opening the PR

```sh
cargo fmt --all --check
cargo clippy -p secure-gate --tests --benches --features=full -- -D warnings
cargo clippy -p secure-gate --tests --benches --all-features -- -D warnings
cargo clippy -p secure-gate --tests --benches --no-default-features --features=alloc,encoding-base32 -- -D warnings
cargo test  -p secure-gate --tests --no-default-features --features=alloc,encoding-base32 -- --skip compile_fail --skip serializable_secret_misuse
cargo test  -p secure-gate --tests --no-default-features --features=alloc,encoding         -- --skip compile_fail --skip serializable_secret_misuse
cargo test  -p secure-gate --tests --features=full                                          -- --skip compile_fail --skip serializable_secret_misuse
cargo test  -p secure-gate --tests --all-features                                           -- --skip compile_fail --skip serializable_secret_misuse
cargo test  -p secure-gate --doc   --features=full
cargo test  -p secure-gate --doc   --all-features
cargo test  -p secure-gate --tests --release --features=full -- --skip compile_fail --skip serializable_secret_misuse   # build-invariance oracle
cargo build -p secure-gate --lib --target thumbv7em-none-eabihf --no-default-features --features encoding-base32
cargo +1.85 check --features=full                                        # MSRV
cargo +1.85 test  -p secure-gate --features=full --test compile_fail_tests
cd secure-gate-core && cargo +nightly fuzz run encoding -- -max_total_time=90 && cd ..
./secure-gate-core/test_all.sh
```

Also run the three `heap_zeroize` configurations CI uses (`--features alloc`, the ASan job's
invocation, and `--no-default-features --features=std`).

## 6. Acceptance criteria

- [ ] `encoding-base32` exists, is in `encoding` and `full`, and enabling it alone (with
      `alloc`) builds, lints clean, and passes tests.
- [ ] `--no-default-features --features encoding-base32` cross-builds for
      `thumbv7em-none-eabihf`; `Fixed::try_from_base32` and the `fixed_newtype!` forwarding of
      it are available there.
- [ ] `key.to_base32()` works on `Fixed<[u8; N]>`, `Dynamic<Vec<u8>>`, and shaped newtypes with
      `use secure_gate::ToBase32;` in scope, and a `S: ToBase32` bound accepts all three.
- [ ] `Dynamic<String>` and `generic` newtypes get no base32 surface.
- [ ] Every vector in §3.3 round-trips; every rejection in §3.4 is a test.
- [ ] `Base32Error` and `DecodingError::InvalidBase32` match the shape/derive/`non_exhaustive`
      contract of the existing errors; `error_tests.rs` covers Display and `source()`.
- [ ] `heap_zeroize.rs` proves the `Dynamic::try_from_base32` buffer is zeroized on drop.
- [ ] Fuzz `encoding` target exercises base32 with the `base32` crate as oracle and survives
      the 90 s quick run.
- [ ] CI test matrix and no-std feature lists include the feature; `test_all.sh` updated.
- [ ] README, SECURITY.md (dependency list, feature table, grep list), both CHANGELOGs, macro
      rustdoc, and every `cfg(any(...))` feature list in `src/` mention the feature — grep for
      `encoding-base64` and `__sg_if_base64` and confirm each hit has a base32 twin where one
      makes sense.
- [ ] `cargo doc --all-features` has no new broken intra-doc links (baseline: 17 pre-existing).

## 7. Estimated effort

| Phase | Estimate |
|---|---|
| 0–1 Dependency, features, errors | 20 min |
| 2–3 Traits + wrapper impls (mostly transcription) | 45 min |
| 3b Newtype macro forwarding + surface tests | 30 min |
| 4 Crate-root docs and re-exports | 20 min |
| 5 Tests | 60 min |
| 6 Fuzz | 30 min |
| 7 CI / matrix | 15 min |
| 8 Docs / changelogs | 40 min |
| 9 Verification (build time dominated) | 45 min |
| **Total** | **≈ 5 h** |

## 8. Non-goals and follow-up candidates

| Item | Mechanism if wanted | Why not now |
|---|---|---|
| Lowercase Base32 (`to_base32_lower`, `try_from_base32_lower`) | `base32ct::Base32Unpadded`, added in both directions together, plus macro forwarding | No mixed decoder in `base32ct`; adding encode-only breaks round-trip symmetry (D1) |
| Accept `=`-padded input | `s.trim_end_matches('=')` (zero-copy) before the unpadded decoder; flip `rejects_padding` test | Strict single-form policy, same as base64url (D2) |
| Accept either case on decode | Dispatch on first alphabetic char, or try Upper then Lower | Second audit path; prefer explicit `_lower` methods |
| base32hex (RFC 4648 §7), Crockford, z-base-32 | Not in `base32ct`; would need another backend | Out of scope; no constant-time backend available |
| Consistent too-long-input error across alloc/no-alloc paths (`InvalidLength` vs `InvalidBase32`) | Map `base32ct::Error::InvalidLength` on the no-alloc path to `InvalidLength { expected: N, got: s.len() * 5 / 8 }` | Pre-existing divergence in base64 too; fix all formats in one change (D4) |
| Error-path partial-decode residue in `*ct::decode_vec` | Decode into a caller-owned `Zeroizing<Vec<u8>>` via `decode` instead of `decode_vec` so a failed decode's partial output is wiped | Applies equally to hex/base64 today; separate issue |
| `otpauth://` URI builder / TOTP helpers | Out of scope for an encoding crate | — |
| Backport to `release/0.8` | Same change against the 0.8 tree once #156 is backported there (the changelog says that is planned) | Land on 0.9 first |

## 9. Risks

- **`base32ct` is pre-1.0 (0.3.1; ~108 K downloads vs. ~226 M for `base16ct` and ~386 M for
  `base64ct`).** Mitigations: pinned to `"0.3"`; the API used is four items
  (`Base32UpperUnpadded`, `Encoding::{encode_string, decode_vec, decode}`); the whole crate is
  ~300 lines with no dependencies and was reviewed while writing this plan; 0.3.1's only change
  was a panic-avoidance fix on the decode path. A future 0.4 would be a one-line version bump
  unless the `Encoding` trait changes shape.
- **MSRV bumps in patch releases** are RustCrypto policy for all three `*ct` crates alike; the
  workspace's `incompatible-rust-versions = "fallback"` resolver setting keeps `cargo update`
  from selecting one the 1.85 toolchain cannot build.
- **Lenient trailing bits (D5)** mean two distinct strings can decode to the same bytes. This is
  irrelevant to secrecy but matters if anyone ever uses the *encoded* string as an identity key;
  documented on the decoding trait and pinned by a test.
- **Case strictness surprises users** who paste lowercase from a third-party UI. The error is
  immediate and the docs say how to normalise; if it becomes a recurring complaint, the
  explicit `_lower` methods in §8 are the answer, not silent tolerance.
- **Macro drift.** The newtype macros duplicate the per-format wiring by hand (`__sg_if_*`
  helper plus a block in each front end). Forgetting one front end compiles fine and silently
  leaves that newtype shape without base32; the `newtype_surface.rs` additions in Phase 3b are
  what catch it.

## 10. Revision history

- **r2 (post `0.9.0-rc.8`)** — rebased on the #156 restructure: wrapper encoders are trait
  impls, decode constructors stay inherent; added Phase 3b for the #155 newtype macros; added
  the generic-bound test and acceptance criteria; refreshed every line reference; verification
  commands use the new `--skip compile_fail` convention and the `--all-features` matrix entries.
- **r1** — initial plan against `8e980b7`.
