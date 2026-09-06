# Plan: Base32 (RFC 4648) encoding via `base32ct`

| | |
|---|---|
| **Status** | Proposed |
| **Tracking issue** | [#158](https://github.com/Slurp9187/secure-gate/issues/158) |
| **Target** | 0.9.0 or any later 0.9.x — additive, no breaking change |
| **Feature flag** | `encoding-base32` (folded into `encoding` → `full`) |
| **Backend** | [`base32ct`](https://github.com/RustCrypto/formats/tree/master/base32ct) 0.3.x (RustCrypto/formats) |
| **Sibling precedent** | `encoding-base64` / `base64ct` — this plan mirrors it file-for-file |

## 1. Goal

Add a fifth encoding format to `secure-gate-core`, Base32 per RFC 4648 §6, with exactly the
shape the four existing formats have:

- an encoding trait (`ToBase32`) with plain and `_zeroizing` methods, blanket-implemented for
  `AsRef<[u8]>`;
- a decoding trait (`FromBase32Str`) blanket-implemented for `AsRef<str>`;
- inherent conveniences on `Fixed<[u8; N]>` (including the no-alloc stack decode path) and
  `Dynamic<Vec<u8>>`;
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
| `[0x00; 1]` | `AA` | `AA======` |
| `[0x00; 3]` | `AAAAA` | `AAAAA===` |
| `[0x07; 32]` | `A4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQ` (52 chars) | `…A4DQ====` |
| `[0xAA; 20]` (TOTP seed size) | `VKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVK` (32 chars) | same (20 ≡ 0 mod 5) |

Encoded lengths for comparison: 20 bytes → 32 chars (hex 40, base64url 27);
32 bytes → 52 chars (hex 64, base64url 43). `encoded_len::<Base32UpperUnpadded>(n)` is a
`const fn` if a stack buffer size is ever needed.

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

### D3 — Naming

| Item | Name | Precedent |
|---|---|---|
| Feature | `encoding-base32` | `encoding-base64` |
| Encode trait / methods | `ToBase32` — `to_base32()`, `to_base32_zeroizing()` | `ToBase64Url` — `to_base64url()`, `to_base64url_zeroizing()` |
| Decode trait / method | `FromBase32Str` — `try_from_base32()` | `FromBase64UrlStr` — `try_from_base64url()` |
| Inherent on `Fixed` / `Dynamic` | `to_base32`, `to_base32_zeroizing`, `try_from_base32` | same shape as base64 |
| Error | `Base32Error::{InvalidBase32, InvalidLength { expected, got }}` | `Base64Error` |
| Unified error variant | `DecodingError::InvalidBase32(#[source] Base32Error)` | `InvalidBase64` |
| Modules | `traits/encoding/base32.rs`, `traits/decoding/base32.rs` | `base64_url.rs` |

No "url"/"upper" qualifier in the name: there is one form (D1), and a qualifier would invite a
second. If D1 is ever relaxed, the *new* variants get the qualifier.

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

Each phase leaves the tree compiling and green. Line numbers refer to the tree at the time of
writing and are there to make the touch points easy to find, not as targets to preserve.

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
- `full` already includes `encoding`; no change.
- Regenerate `Cargo.lock` with the pinned toolchain (`cargo update -p base32ct` or a plain
  build). The workspace `.cargo/config.toml` MSRV-aware resolver will refuse a future
  `base32ct` release whose `rust-version` exceeds 1.85.
- `secure-gate-compat` forwards no encoding features; nothing to do there.

### Phase 1 — Error types (`src/error.rs`)

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

**`src/traits/encoding/base32.rs` (new)** — mirror `base64_url.rs`:

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
//! assert_eq!(secret.to_base32(), "IJBEEQQ");
//! let b32z = secret.to_base32_zeroizing(); // EncodedSecret — zeroized on drop, redacted Debug
//! }
//! ```
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
use base32ct::{Base32UpperUnpadded, Encoding};

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
- `src/traits/mod.rs`: re-exports (lines 72–99); add `encoding-base32` to **all four**
  `cfg(any(...))` lists on `SecureEncoding` / `SecureDecoding` and their impls (lines 111–151);
  update the doc table rows for those two markers (lines 22–23).
- `src/traits/revealed_secrets/encoded_secret.rs`: add the feature to the `cfg(any(...))` on
  `EncodedSecret::new` (lines 59–64). Mention `to_base32_zeroizing` in the module docs of
  `encoded_secret.rs` (line 7) and `revealed_secrets/mod.rs` (line 10).

### Phase 3 — Inherent methods

**`src/fixed.rs`**

- Import next to the others (line 94):
  `#[cfg(all(feature = "encoding-base32", feature = "alloc"))] use crate::traits::encoding::base32::ToBase32;`
- Constructor table (line 166): `| [`try_from_base32`](Self::try_from_base32) | `encoding-base32` | Constant-time Base32 decoding |`
- New impl block directly after the base64 block (after line 611), a copy of lines 490–611 with
  names swapped and `[0xDE, 0xAD, 0xBE, 0xEF]` ↔ `"32W353Y"` as the doctest vector:

  ```rust
  /// Base32 encoding and decoding for `Fixed<[u8; N]>`.
  ///
  /// Encoding uses a constant-time backend (`base32ct`). Decoding works with or without
  /// the `alloc` feature — on no-alloc targets the bytes are decoded directly into a
  /// `Zeroizing<[u8; N]>` stack buffer.
  #[cfg(feature = "encoding-base32")]
  impl<const N: usize> Fixed<[u8; N]> {
      #[cfg(feature = "alloc")]
      #[inline]
      pub fn to_base32(&self) -> alloc::string::String {
          self.with_secret(|s: &[u8; N]| s.to_base32())
      }

      #[cfg(feature = "alloc")]
      #[inline]
      pub fn to_base32_zeroizing(&self) -> crate::EncodedSecret {
          self.with_secret(|s: &[u8; N]| s.to_base32_zeroizing())
      }

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

  Doc comments (omitted above for brevity) copy the base64 ones verbatim with names swapped,
  including the `# Errors` list and the feature-gated doctests.

**`src/dynamic.rs`**

- Add `feature = "encoding-base32"` to the `cfg(any(...))` that imports `RevealSecret`
  (lines 102–109).
- Imports: `ToBase32` next to line 113, `FromBase32Str` next to line 127 (both gated on
  `encoding-base32` only — `Dynamic` is always `alloc`).
- Constructor table (line 166): `| [`try_from_base32(s)`](Self::try_from_base32) | `encoding-base32` | Constant-time Base32 decoding |`
- New impl block after the base64 block (after line 304):

  ```rust
  // Base32 encoding and decoding for Dynamic<Vec<u8>>.
  #[cfg(feature = "encoding-base32")]
  impl Dynamic<Vec<u8>> {
      /// Encodes the secret bytes as an uppercase, unpadded Base32 string (RFC 4648 §6).
      #[inline]
      pub fn to_base32(&self) -> alloc::string::String {
          self.with_secret(|s: &Vec<u8>| s.to_base32())
      }

      /// Encodes the secret bytes as Base32, returning [`EncodedSecret`](crate::EncodedSecret).
      #[inline]
      pub fn to_base32_zeroizing(&self) -> crate::EncodedSecret {
          self.with_secret(|s: &Vec<u8>| s.to_base32_zeroizing())
      }

      /// Decodes an uppercase, unpadded Base32 string into `Dynamic<Vec<u8>>`.
      ///
      /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
      /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
      pub fn try_from_base32(s: &str) -> Result<Self, crate::error::Base32Error> {
          Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(s.try_from_base32()?)))
      }
  }
  ```

The compile-fail probe `tests/compile-fail/dynamic_string_no_hex.rs` already proves the
"no encoding methods on `Dynamic<String>`" property generically (E0599 on `to_hex`); adding a
`to_base32` line would only change the blessed `.stderr`. Leave it.

### Phase 4 — Crate root (`src/lib.rs`)

- Module tree comment (lines 91–94): add `ToBase32`, `FromBase32Str`, `Base32Error`.
- Feature table (after line 175):
  `| `encoding-base32` | no | [`ToBase32`] / [`FromBase32Str`] via `base32ct` (constant-time) |`
- "What's available without `alloc`" (line 188): add `Fixed::try_from_base32`.
- Re-exports, alphabetical with the existing ones (lines 451–494), each with the same
  two-line doc style:
  `pub use traits::FromBase32Str;` / `pub use traits::ToBase32;` under
  `cfg(all(feature = "encoding-base32", feature = "alloc"))`, and
  `pub use error::Base32Error;` under `cfg(feature = "encoding-base32")`.
- Add the feature to both `cfg(any(...))` lists on the `SecureDecoding` / `SecureEncoding`
  re-exports (lines 498–514); mention `Base32Error` in the `DecodingError` doc (line 533).

### Phase 5 — Tests

**`tests/encoding_suite/base32.rs` (new) + `mod base32;` in `encoding_suite/mod.rs`.**
Mirror `base64.rs` test-for-test with the §3.3/§3.4 vectors, then add the base32-specific
cases. Every test carries the same `cfg` gates as its base64 twin.

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

**`tests/proptest_suite/encoding.rs`:** add a `b32_roundtrip` module identical to
`b64_roundtrip` (256 cases, same length distribution) using `to_base32` /
`Dynamic::try_from_base32`.

**`tests/error_tests.rs`:**

- Add `encoding-base32` to the two `cfg(any(...))` lists (lines 16–20, 90–94).
- `base32_error_invalid_length`: `Fixed::<[u8; 2]>::try_from_base32("32W353Y")` →
  `InvalidLength { expected: 2, got: 4 }`, Display `"decoded length mismatch: expected 2, got 4"`.
- `decoding_error_source_base32`: `DecodingError::InvalidBase32(Base32Error::InvalidBase32)`
  has a `source()` whose Display contains `"invalid base32"`.

**`tests/heap_zeroize.rs`:** add `check_decode_base32_zeroed(data: &[u8])` next to the base64
one (lines 316–334, same `shrink_to_fit` + proxy-window pattern) and call it with
`[0xAAu8; 16]` and `[0xBBu8; 32]` beside the base64 calls (line 632). Update the comment at
line 294 ("hex, base32, base64url, bech32, bech32m").

### Phase 6 — Fuzz (`secure-gate-core/fuzz/`)

- `Cargo.toml`: `encoding-base32 = ["secure-gate/encoding-base32"]` in `[features]`; add the
  independent oracle `base32 = "0.5"` under "Direct deps for encoding round-trip verification"
  (the same crate `base32ct`'s own equivalence tests use). The `encoding` meta already
  forwards the new feature, so the default feature set picks it up.
- `src/arbitrary.rs`: `FuzzBase32String(pub String)` generated as
  `base32::encode(base32::Alphabet::Rfc4648 { padding: false }, capped)` (cap 512 bytes like
  the others). Because the oracle produces canonical uppercase unpadded strings, the
  "stable re-encoding" check below is valid (D5).
- `fuzz_targets/encoding.rs`: a `=== BASE32 ===` section between base64 and bech32 with the
  four sub-blocks the base64 section has: (a) arbitrary strings into
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

- `.github/workflows/ci.yml` `test` matrix, after `encoding-base64 only`:

  ```yaml
          - name: encoding-base32 only
            features: "--no-default-features --features=alloc,encoding-base32"
  ```

- `.github/workflows/ci.yml` `no-std` job feature list (lines 244–252): add
  `"encoding-base32" \` and extend both combined lines to
  `"encoding-hex,encoding-base32,encoding-base64,encoding-bech32,encoding-bech32m"` (and the
  `ct-eq,…` twin). This is the only job that compiles the no-alloc `try_from_base32` path.
- `lint`, `test-release`, `msrv`, `compile-fail` already run with `full` and pick the feature
  up automatically.
- `secure-gate-core/test_all.sh`: add
  `run_tests "encoding-base32 only" "--no-default-features --features=encoding-base32"`
  beside the base64 line. (The script's encoding entries predate CI's `alloc,` prefix; follow
  whichever convention is current when landing this.)

### Phase 8 — Documentation

- **`secure-gate-core/README.md`**: line 140 (feature bullet), line 166 ("four formats" →
  "five formats: hex, base32, base64url, bech32, bech32m"), trait table (172–175), the
  encode/zeroizing/scoped examples (185–206: add `to_base32` lines), the sentence at 209,
  decode constructor table (218: `| Base32 | `try_from_base32(s)` | `Base32Error` (RFC 4648 §6,
  uppercase, unpadded) |`), method lists at 299–300, feature table (331–334). One sentence on
  TOTP/`otpauth://` under the format table earns its place; keep it to one.
- **`secure-gate-core/SECURITY.md`**: line 23 (zeroizing variants list), line 116 (dependency
  list: `base32ct` — constant-time Base32 encoding/decoding (RustCrypto)), feature table
  rows 208–210, method lists at 231, 249, 379, the grep list at 391–392 (`to_base32`,
  `to_base32_zeroizing`), and the two-flavour table at 418–423.
- **`secure-gate-core/CHANGELOG.md`** `[Unreleased]` → `### Added`:

  > **Base32 encoding (`encoding-base32`, #158).** `ToBase32` / `FromBase32Str`, inherent
  > `to_base32` / `to_base32_zeroizing` / `try_from_base32` on `Fixed<[u8; N]>` and
  > `Dynamic<Vec<u8>>`, and `Base32Error`. RFC 4648 §6 alphabet, uppercase, unpadded — the
  > `otpauth://` TOTP/HOTP form — via the constant-time `base32ct` crate. Strict decoding:
  > lowercase and `=` padding are rejected. Included in the `encoding` and `full`
  > meta-features; `Fixed::try_from_base32` works without `alloc`.

- **Root `CHANGELOG.md`** `[Unreleased]`: one pointer line to the core entry, as the existing
  entries do.

### Phase 9 — Verification before opening the PR

```sh
cargo fmt --all --check
cargo clippy -p secure-gate --tests --benches --features=full -- -D warnings
cargo clippy -p secure-gate --tests --benches --no-default-features --features=alloc,encoding-base32 -- -D warnings
cargo test  -p secure-gate --tests --no-default-features --features=alloc,encoding-base32
cargo test  -p secure-gate --tests --no-default-features --features=alloc,encoding
cargo test  -p secure-gate --tests --features=full
cargo test  -p secure-gate --doc   --features=full
cargo test  -p secure-gate --tests --release --features=full            # build-invariance oracle
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
      `thumbv7em-none-eabihf`; `Fixed::try_from_base32` is available there.
- [ ] Every vector in §3.3 round-trips; every rejection in §3.4 is a test.
- [ ] `Base32Error` and `DecodingError::InvalidBase32` match the shape/derive/`non_exhaustive`
      contract of the existing errors; `error_tests.rs` covers Display and `source()`.
- [ ] `heap_zeroize.rs` proves the `Dynamic::try_from_base32` buffer is zeroized on drop.
- [ ] Fuzz `encoding` target exercises base32 with the `base32` crate as oracle and survives
      the 90 s quick run.
- [ ] CI test matrix and no-std feature lists include the feature; `test_all.sh` updated.
- [ ] README, SECURITY.md (dependency list, feature table, grep list), both CHANGELOGs, and
      every `cfg(any(...))` feature list in `src/` mention the feature — grep for
      `encoding-base64` and confirm each hit has a base32 twin where one makes sense.
- [ ] `cargo doc --all-features` has no broken intra-doc links.

## 7. Estimated effort

| Phase | Estimate |
|---|---|
| 0–1 Dependency, features, errors | 20 min |
| 2–3 Traits + inherent methods (mostly transcription) | 45 min |
| 4 Crate-root docs and re-exports | 20 min |
| 5 Tests | 60 min |
| 6 Fuzz | 30 min |
| 7 CI / matrix | 15 min |
| 8 Docs / changelogs | 40 min |
| 9 Verification (build time dominated) | 45 min |
| **Total** | **≈ 4.5 h** |

## 8. Non-goals and follow-up candidates

| Item | Mechanism if wanted | Why not now |
|---|---|---|
| Lowercase Base32 (`to_base32_lower`, `try_from_base32_lower`) | `base32ct::Base32Unpadded`, added in both directions together | No mixed decoder in `base32ct`; adding encode-only breaks round-trip symmetry (D1) |
| Accept `=`-padded input | `s.trim_end_matches('=')` (zero-copy) before the unpadded decoder; flip `rejects_padding` test | Strict single-form policy, same as base64url (D2) |
| Accept either case on decode | Dispatch on first alphabetic char, or try Upper then Lower | Second audit path; prefer explicit `_lower` methods |
| base32hex (RFC 4648 §7), Crockford, z-base-32 | Not in `base32ct`; would need another backend | Out of scope; no constant-time backend available |
| Consistent too-long-input error across alloc/no-alloc paths (`InvalidLength` vs `InvalidBase32`) | Map `base32ct::Error::InvalidLength` on the no-alloc path to `InvalidLength { expected: N, got: s.len() * 5 / 8 }` | Pre-existing divergence in base64 too; fix all formats in one change (D4) |
| Error-path partial-decode residue in `*ct::decode_vec` | Decode into a caller-owned `Zeroizing<Vec<u8>>` via `decode` instead of `decode_vec` so a failed decode's partial output is wiped | Applies equally to hex/base64 today; separate issue |
| `otpauth://` URI builder / TOTP helpers | Out of scope for an encoding crate | — |

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
