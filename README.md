# secure-gate

[![Crates.io](https://img.shields.io/crates/v/secure-gate.svg)](https://crates.io/crates/secure-gate)
[![Docs.rs](https://docs.rs/secure-gate/badge.svg)](https://docs.rs/secure-gate)
[![CI](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml)
[![MSRV: 1.85](https://img.shields.io/badge/msrv-1.85-blue)](https://github.com/Slurp9187/secure-gate/blob/main/Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

Secure wrappers for secrets with **explicit access** and **mandatory zeroization** — a `no_std`-compatible, zero-overhead library with audit-friendly access patterns.

> [!WARNING]
> **Security Notice**: This crate has **not undergone independent audit**.
> Review the code and [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) before production use.

## Quick Start

```rust
use secure_gate::{Dynamic, Fixed, RevealSecret, RevealSecretMut};

pub type Password = Dynamic<String>;     // heap, length varies with the input
pub type Aes256Key = Fixed<[u8; 32]>;    // on the stack, exactly 32 bytes

let mut pw: Password = "hunter2".into();

// Generate key material from the system RNG rather than a literal (needs `rand`).
let mut key: Aes256Key = Aes256Key::from_random();

// Scoped access — preferred; the borrow cannot outlive the closure
let long_enough = pw.with_secret(|s| s.len() >= 8); // validate in-closure; never log a secret's length

// Mutable scoped access — rotate in fresh material. The old key is overwritten in
// place and never leaves the wrapper. For Dynamic<String> / Dynamic<Vec<u8>>, prefer
// capacity-stable mutations or pre-allocate before wrapping; see SECURITY.md.
let next: Aes256Key = Aes256Key::from_random();
next.with_secret(|fresh| key.with_secret_mut(|old| old.copy_from_slice(fresh)));

// Direct reference — auditable escape hatch (e.g. FFI, third-party APIs)
assert_eq!(pw.expose_secret(), "hunter2");
pw.expose_secret_mut().clear();

#[cfg(all(feature = "encoding-hex", feature = "encoding-bech32"))]
{
    use secure_gate::{Case, RevealSecret, ToHex, ToBech32, FromHexStr};

    let key: Fixed<[u8; 32]> = Fixed::new([42u8; 32]);

    // Encode to hex (scoped borrow — no long-lived reference)
    let hex = key.with_secret(|bytes| bytes.to_hex()); // EncodedSecret

    // Encode to Bech32 (BIP-173) with human-readable prefix "key"
    let bech32 = key.with_secret(|bytes| {
        bytes.try_to_bech32("key", Case::Lower).expect("valid bech32")
    });

    // Round-trip demonstration (decode hex back to bytes)
    let decoded: Vec<u8> = hex.try_from_hex().expect("valid hex");

    // Optional: assert round-trip (useful in real code / tests)
    key.with_secret(|original| assert_eq!(decoded, original));
}
```

## Core Concepts

`Fixed<T>` (stack-allocated) and `Dynamic<T>` (heap, requires `alloc`) share the same access interface:

- `Debug` output → `[REDACTED]`
- `.len()` / `.is_empty()` via `SecretLen` — without exposing contents (length itself can still be sensitive)
- Zeroize on drop (always)
- Access via `.with_secret(|s| ...)` (preferred) or `.expose_secret()` (auditable escape hatch)
- Owned extraction via `.into_inner()` → the plain `T`; nothing is copied and protection ends at the call
- Streaming I/O via `impl Write` and `.as_reader()` for `Dynamic<Vec<u8>>` (requires `std`)

### Preferred: scoped access

```rust
use secure_gate::{Fixed, RevealSecret, RevealSecretMut};

let mut key: Fixed<[u8; 32]> = Fixed::new([0xAB; 32]);

// Read — the closure borrow cannot outlive the call, so validate inside it and
// return only the verdict, never the bytes.
let looks_degenerate = key.with_secret(|bytes| bytes.iter().all(|&b| b == bytes[0]));
assert!(looks_degenerate); // every byte is 0xAB

// Mutate in place — the secret is never copied out to be modified.
key.with_secret_mut(|bytes: &mut [u8; 32]| bytes.copy_from_slice(&[0xCD; 32]));
```

### RustCrypto in-place cipher ops

`BlockEncrypt`/`BlockDecrypt` take `&mut GenericArray<u8, U16>`, and
`GenericArray::from_mut_slice` *borrows* rather than copies — so the cipher can run
inside the wrapper and the plaintext never leaves it:

```rust
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
use secure_gate::{Fixed, RevealSecretMut};

let cipher = Aes128::new(GenericArray::from_slice(&[0x42u8; 16]));
let mut block: Fixed<[u8; 16]> = Fixed::new([0u8; 16]);

block.with_secret_mut(|b| cipher.decrypt_block(GenericArray::from_mut_slice(b)));
```

Copying out instead — `block.with_secret(|b| aes::Block::from(*b))` — is the footgun:
the resulting `Block` is an ordinary stack value that nothing wipes on drop. See the
[`Fixed` rustdoc](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html)
for both shapes side by side.

### Direct reference — auditable escape hatch

```rust
// Use only when a long-lived reference is unavoidable (FFI, third-party APIs)
use secure_gate::{Fixed, RevealSecret};
let key: Fixed<[u8; 32]> = Fixed::new([0xAB; 32]);
let raw: &[u8; 32] = key.expose_secret();
```

### Owned consumption — transfer ownership

```rust
// When you need to move the secret value out (FFI hand-off, type migration)
use secure_gate::{Fixed, RevealSecret};
let key: Fixed<[u8; 32]> = Fixed::new([0xAB; 32]);
let owned: [u8; 32] = key.into_inner();
// Protection ends here: `owned` is a plain array and you own its lifetime.
// Nothing was copied — the bytes were moved out and a sentinel left behind.
assert_eq!(owned, [0xAB; 32]);
```

### Named secret types

Two ways to give a secret a name, differing in exactly one respect — whether the compiler can tell two same-shaped secrets apart.

**A plain `type` alias** over `Fixed` or `Dynamic` is a name and nothing more: the alias *is* the wrapper, so it carries every guarantee the wrapper carries — zeroize on drop, redacted `Debug`, access only through `RevealSecret` — and it stays interchangeable with its base type. Two aliases over the same underlying type are the **same** nominal type and assignable to each other — use them for readability and audit grep targets. Documentation goes on the alias as an ordinary doc comment, which is also where the doc string the removed `*_alias!` macros took now belongs:

```rust
use secure_gate::{Dynamic, Fixed};

/// 32-byte AES-256 key.
pub type Aes256Key = Fixed<[u8; 32]>;

#[cfg(feature = "alloc")]
/// Variable-length password.
pub type Password = Dynamic<String>;
```

A plain `type` alias is the right reach when a value is sensitive enough to want zeroize-on-drop and a redacted `Debug`, but has no role it could be confused *with* — a session blob, a cached token, a nonce store. You get the protection and a self-documenting name, the alias stays interchangeable with its base type so it crosses into APIs you do not own without ceremony, and there is no cross-contamination to prevent because nothing else shares its shape and meaning.

Reach for a newtype the moment two values of the same shape mean different things. That is the case the compiler can help with, and the only one where the extra surface pays for itself.

**Newtypes** (`fixed_newtype!`, `dynamic_newtype!`) expand to `struct`s instead, so two of the same shape are **distinct** types. Reach for these when distinct cryptographic roles share a shape — an encryption key and a MAC key are both `Fixed<[u8; 32]>`, and under an alias the compiler cannot tell them apart:

```rust
use secure_gate::fixed_newtype;

fixed_newtype!(pub EncKey, 32, "AES-256 key. Never used for authentication.");
fixed_newtype!(pub MacKey, 32, "HMAC-SHA256 key. Never used for encryption.");

fn seal(enc: &EncKey, mac: &MacKey) { /* … */ }

// seal(&mac, &enc) does not compile — the roles cannot be swapped by accident.
```

Both newtype macros also accept `generic T` in place of the byte size `fixed_newtype!` expects or the `String` / `Vec<u8>` `dynamic_newtype!` expects, for a secret whose inner type is neither bytes nor a string — `fixed_newtype!(pub Poly, generic [i16; 256]);` for an ML-KEM secret polynomial on a target with no allocator, where `Fixed` is the only wrapper there is. The `generic` arm emits exactly the surface that is meaningful for an arbitrary inner type: scoped access, redacted `Debug`, zeroize on drop and `new`, with no `SecretLen` and no encoders, since neither has a meaning without a known shape.

Generated newtypes carry the same guarantees as the wrapper (zeroize on drop, redacted `Debug`, access only via `RevealSecret`), are `#[repr(transparent)]` so they cost nothing at runtime, and have no `Deref` — the separation is total, not by-value-only. No `From<Wrapper>` or `Deref` is generated, so an alias-typed value cannot become a newtype through `.into()` and a newtype never coerces back to its base; base-wrapper access is opt-in per newtype and split by direction (`derive: [FromWrapper]` to construct from the base, `derive: [IntoWrapper]` to reach it; `WrapperAccess` is both) and should be audited like `expose_secret()`. In a mixed tree the base type is the pool every plain alias lives in: `FromWrapper` on a boundary type accepts all of them, and `IntoWrapper` on a secret role downgrades it to the least-sensitive alias sharing its base — neither token is the sufficient default more often than it looks.

See [`fixed_newtype!`] and [`dynamic_newtype!`] in the [API docs](https://docs.rs/secure-gate).

**Zero-size behavior note**  
A zero-length `Fixed` cannot be built at all. `Fixed::new` and `Fixed::new_with` each carry a `const` assertion that the value being wrapped has a nonzero size, so `Fixed<[u8; 0]>` — and any other zero-sized inner type — is a compile error at the first construction. The assertion is a post-monomorphization error, which is what makes it cover generic code too. Where it points is worth knowing before you go looking. The error's own span is the assertion inside this crate, not your code; a separate `while instantiating` note is what names the `Fixed::new` call the monomorphization reached. That note does **not** name the instantiation that caused it. Given a generic `fn build<const N: usize>() -> Fixed<[u8; N]>`, calling `build::<0>()` reports against the `Fixed::new` line inside `build`, and neither `build::<0>()` nor its caller appears anywhere in the output. `fixed_newtype!(Name, 0)` additionally fails at the declaration, via a const-eval index-out-of-bounds guard in the macro, so that spelling reports the problem at the line you wrote rather than at the first call.

**Two limits on when it fires, both measured rather than assumed.** First, a post-monomorphization error is raised during codegen, so `cargo check` does not report it, and neither does an editor driven by `cargo check`. Second, and more consequential: it only fires for a codegen root. A non-generic `#[inline]` function in a library is not one, and every method these macros generate carries an inline attribute, `#[inline]` or `#[inline(always)]`. So a library crate that writes `fixed_newtype!(pub Empty, generic [u8; 0]);` alongside `#[inline] pub fn empty() -> Empty { Empty::new([]) }` compiles, tests and publishes with `cargo build`, `cargo build --release` and `cargo test` all green. The error surfaces only when a downstream crate instantiates it, and the diagnostic points into `secure-gate` and at the dependency's macro invocation — not at the consumer's own call site, and not in the crate that wrote the bug.

So state the guarantee precisely: no **value** of a zero-sized `Fixed` can exist at runtime, because nothing can construct one. A binary or a test that builds one fails to compile. What the guard does not do is stop a library from *exporting* an unusable zero-sized API with green CI. Neither limit is a design choice: a condition on a generic parameter has nothing to evaluate until that parameter is known, and nothing on stable Rust moves it earlier. `fixed_newtype!(Name, 0)` is the exception that does fire under `cargo check` in the declaring crate, because the size is a literal at that point — which is the argument for the macro's own guard earning its keep alongside this one.

Naming the type still compiles: `type Empty = Fixed<[u8; 0]>;` is a legal type expression, and no guard placed in the type can make the type itself unnameable. What the assertion removes is every value of it — there is no way to obtain an `Empty` to hold, encode, compare or drop — which is the property that matters, and it holds for a plain `type` alias and a newtype alike because both funnel through the same two constructors.

`Dynamic` has no compile-time equivalent, and the reason is about the payload rather than the wrapper: the emptiness of a `Vec` or a `String` is a runtime property, and an empty `Dynamic<String>` is a legitimate value to hold before validation, so there is nothing for a compile-time check to decide. One honest gap remains, rather than a non-problem: a *statically* zero-sized inner type. `Dynamic<Zst>` constructs where `Fixed<Zst>` is now rejected, so do not reach for a zero-sized inner type expecting to be stopped. A zero-length `Dynamic` then behaves normally rather than failing: `len()` is 0, `Debug` is still `[REDACTED]`, `ct_eq` against another empty is `true`, `to_hex()` returns `""`, and drop is clean. Nothing reports a problem, which is precisely why this is worth stating — the failure is silent and semantic, not a panic you would notice. Validate that the effective length is > 0 in your own tests whenever it comes from configuration.

See also the Best Practices section in [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for the equivalent guidance.

### Polymorphic / generic code

```rust
use secure_gate::SecretLen;

// Length is metadata, not contents — but for variable-length secrets it can
// still be sensitive. Validate against it; don't log it.
fn require_min_len<S: SecretLen>(secret: &S, min: usize) -> bool {
    secret.len() >= min
}
```

## What You Get

- **Zero-cost safety** — mandatory zeroization on drop; `no_std` / `no_alloc` support.
- **Audit-first API** — a held secret cannot leak via `Deref`: `Fixed`/`Dynamic` implement none. Access requires explicit `with_secret` scopes or an auditable `expose_secret` escape hatch. `into_inner` hands ownership to the caller and ends protection; encoders return `EncodedSecret`, which *does* deref and stays wiped until it drops — see [Where accident-prevention ends](SECURITY.md#where-accident-prevention-ends).
- **Named secret types** — a plain `type` alias over `Fixed` / `Dynamic` (`pub type Aes256Key = Fixed<[u8; 32]>;`) inherits redacted `Debug` and zeroize-on-drop and stays interchangeable with its base type, so same-shape aliases (e.g. two `Fixed<[u8; 32]>` aliases) are one and the same type. When distinct cryptographic roles share a shape, `fixed_newtype!` / `dynamic_newtype!` generate `struct`s instead, so the compiler rejects a swapped key role at the call site.
- **Batteries included** — optional, zero-overhead support for serde, constant-time comparison (`subtle`), and secure encoding (hex, base32, base64url, bech32/m).
- **No unsafe code** — enforced with `#![forbid(unsafe_code)]`.

## Installation

**Default** (`alloc` enabled — `Fixed<T>` + `Dynamic<T>` + full zeroization):

```toml
[dependencies]
secure-gate = "0.9.0-rc.9"
```

**No-heap / embedded** (`Fixed<T>` only — pure stack / `no_std`):

```toml
secure-gate = { version = "0.9.0-rc.9", default-features = false }
```

**Batteries-included**:

```toml
secure-gate = { version = "0.9.0-rc.9", features = ["full"] }
```

## Encoding & Decoding

`secure-gate` provides symmetric, zero-overhead encoding and decoding for five formats: hex, base32 (RFC 4648 §6), base64url, bech32 (BIP-173), and bech32m (BIP-350). All operations are explicit. Decoding is always fallible; on the encode side only bech32 and bech32m return a `Result`, because they can reject an invalid HRP or an over-long payload — `to_hex`, `to_hex_upper`, `to_base32` and `to_base64url` cannot fail.

### Available traits

| Format               | Encode        | Decode             | Feature            |
| -------------------- | ------------- | ------------------ | ------------------ |
| Hex                  | `ToHex`       | `FromHexStr`       | `encoding-hex`     |
| Base32 (RFC 4648 §6) | `ToBase32`    | `FromBase32Str`    | `encoding-base32`  |
| Base64URL            | `ToBase64Url` | `FromBase64UrlStr` | `encoding-base64`  |
| Bech32 (BIP-173)     | `ToBech32`    | `FromBech32Str`    | `encoding-bech32`  |
| Bech32m (BIP-350)    | `ToBech32m`   | `FromBech32mStr`   | `encoding-bech32`  |

Base32 is here for TOTP/HOTP interop: `otpauth://` key URIs (RFC 6238 / RFC 4226) carry the shared secret as uppercase, unpadded Base32, and Base32 is the densest encoding that fits QR alphanumeric mode.

### Encoding (to string)

The wrapper encoding methods are trait impls, so the trait must be in scope — `use secure_gate::{Case, ToHex, ToBase32, ToBase64Url, ToBech32, ToBech32m};` — before `key.to_base32()` resolves. Every one of them returns [`EncodedSecret`], which wipes itself on drop and prints `[REDACTED]`. Read it through the deref (`&*encoded` is a `&str`) and call `.into_inner()` only when an API demands an owned `String`.

```rust
use secure_gate::{Case, Fixed, RevealSecret, ToHex, ToBase32, ToBase64Url, ToBech32, ToBech32m};
# fn main() -> Result<(), secure_gate::Bech32Error> {
let key: Fixed<[u8; 32]> = Fixed::new([0x42u8; 32]);

// Direct on the wrapper
let hex     = key.to_hex();
let hex_u   = key.to_hex_upper();
let b32     = key.to_base32();
let b64     = key.to_base64url();
let bech32  = key.try_to_bech32("bc", Case::Lower)?;
let bech32m = key.try_to_bech32m("bc", Case::Lower)?;

// Every one of these returns an `EncodedSecret`: it wipes itself on drop and its
// `Debug` is redacted. Call `.into_inner()` when an API needs an owned `String`.

// Scoped on the inner bytes (preferred when you want `with_secret` in audit sweeps)
let hex_scoped     = key.with_secret(|s| s.to_hex());
let b32_scoped     = key.with_secret(|s| s.to_base32());
let b64_scoped     = key.with_secret(|s| s.to_base64url());
let bech32_scoped  = key.with_secret(|s| s.try_to_bech32("bc", Case::Lower))?;
let bech32m_scoped = key.with_secret(|s| s.try_to_bech32m("bc", Case::Lower))?;

# Ok(())
# }
```

Every encoder returns [`EncodedSecret`] — `Zeroizing<String>` with a redacted `Debug` and no `Display` — because an encoded secret is a second full copy of the secret and deserves the same wiping as the first. Read it with `&*encoded` (it derefs to `str`), which is what `serde_json` and every database driver want; call `.into_inner()` for an owned `String`, which is the named moment protection ends. The same methods exist on the wrappers (`Fixed` / `Dynamic`) and on the encoding traits (`ToHex`, `ToBase32`, `ToBase64Url`, `ToBech32`, `ToBech32m`).

### Direct Constructors (Recommended)

Both `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` offer one-shot constructors from strings. Both use panic-safe `Zeroizing`-wrapped decode buffers internally. `Fixed` also supports a no-alloc path that decodes directly into stack storage when `alloc` is disabled.

| Format              | Method                          | Notes                                            |
| ------------------- | ------------------------------- | ------------------------------------------------ |
| Hex                 | `try_from_hex(s)`               | `HexError`                                       |
| Base32              | `try_from_base32(s)`            | `Base32Error` (RFC 4648 §6, uppercase, unpadded) |
| Base64URL           | `try_from_base64url(s)`         | `Base64Error` (unpadded, URL-safe)               |
| Bech32 (BIP-173)    | `try_from_bech32(s, hrp)`       | HRP validated; `Bech32Error::UnexpectedHrp`      |
| Bech32 (unchecked)  | `try_from_bech32_unchecked(s)`  | No HRP; `Bech32Error`                            |
| Bech32m (BIP-350)   | `try_from_bech32m(s, hrp)`      | HRP validated; `Bech32Error::UnexpectedHrp`      |
| Bech32m (unchecked) | `try_from_bech32m_unchecked(s)` | No HRP; `Bech32Error`                            |

**Security notes**:

- Prefer HRP-validated constructors to prevent cross-protocol confusion attacks.
- Use `_unchecked` only when HRP is validated upstream.
- The decode constructors in this table stage into `Zeroizing` buffers, so a panic between a successful decode and wrapper construction still wipes them. (`Fixed::new` / `Dynamic::new` take an already-built value and have no such buffer.)
- Encoded output is protected by default: every encoder returns [`EncodedSecret`], wiped on drop. `.into_inner()` is the named point where that ends (see `SECURITY.md`).

## Serde

`serde-deserialize` decodes directly to the inner type. After deserialization completes, temporary buffers for `Dynamic<Vec<u8>>` and `Dynamic<String>` are `Zeroizing`-wrapped — oversized buffers are zeroized even on rejection. The default limit is `MAX_DESERIALIZE_BYTES` (1 MiB); call `Dynamic::deserialize_with_limit` to set a custom ceiling. Serialization requires the `SerializableSecret` marker trait.

> **Note:** `MAX_DESERIALIZE_BYTES` (and `deserialize_with_limit`) is enforced _after_ the upstream deserializer has fully materialized the payload. It is a result-length acceptance bound, not a pre-allocation DoS guard. For untrusted input, enforce size limits at the transport or parser layer upstream.

See [`SerializableSecret`] in the [API docs](https://docs.rs/secure-gate) for the full example.

## Random Generation

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::Fixed;
    // System RNG — panics if entropy is unavailable (fatal environment error).
    let key: Fixed<[u8; 32]> = Fixed::from_random();
}

#[cfg(all(feature = "rand", feature = "alloc"))]
{
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use secure_gate::{Dynamic, Fixed};

    let mut rng = StdRng::from_seed([0u8; 32]);
    let _fixed: Fixed<[u8; 16]> = Fixed::from_rng(&mut rng).expect("rng fill");
    let _buf: Dynamic<Vec<u8>> = Dynamic::from_rng(32, &mut rng).expect("rng fill");
}
```

`from_random()` uses the system RNG ([`SysRng`](https://docs.rs/rand/latest/rand/rngs/struct.SysRng.html)), panics on failure, and is heap-free for `Fixed<T>` (`no_std` / `no_alloc`). `from_rng` fills from any [`TryCryptoRng`](https://docs.rs/rand/latest/rand/trait.TryCryptoRng.html) + [`TryRng`](https://docs.rs/rand/latest/rand/trait.TryRng.html) and returns `Result` (e.g. seeded `StdRng` in tests). `Dynamic::from_random` / `from_rng` require `alloc` (implicit — `Dynamic<T>` itself already requires it). See [`Fixed::from_random`], [`Fixed::from_rng`], [`Dynamic::from_random`], and [`Dynamic::from_rng`] in the [API docs](https://docs.rs/secure-gate).

## Security Model

- **Explicit access only** — all caller-facing access requires `.with_secret()` / `.expose_secret()`; no silent leaks. Internal impls (`Clone`, `Serialize`) access `.inner` directly but require opt-in marker traits.
- **Zeroize on drop** — always active; inner type must implement `Zeroize`
- **Timing-safe equality** — `ct-eq` feature (`.ct_eq()`) routes through `expose_secret()`, honoring the explicit-access model
- **No unsafe code** — enforced with `#![forbid(unsafe_code)]`

For `Dynamic<Vec<_>>` and `Dynamic<String>`, avoid capacity-changing mutations
after wrapping unless your deployment handles allocator-level residue. For
known-size heap-only key material, prefer `Dynamic<[u8; N]>` (boxed array — no
realloc surface). See `SECURITY.md` for the realloc threat-model note and
operational mitigations.

### Inherent Rust limitations

Three universal in-memory-secret limits apply (same across C, C++, Go, and
Rust): **stack-move residue** (mitigated by `Fixed::new_with`, pass-by-reference,
or switching to `Dynamic<T>`), **heap-reallocation residue** (mitigated by
pre-sizing, `Dynamic<[u8; N]>`, or the
[`zeroizing-alloc`](https://crates.io/crates/zeroizing-alloc) global allocator),
and **swap / core dumps** (OS-level — `mlock`, encrypted swap, disabled core
dumps).

Read [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for the full threat model and mitigations, including the dedicated [§ Inherent Rust Limitations](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md#inherent-rust-limitations) section.

## Audit Surface (Secret Materialization)

Encoding and decoding methods are **convenience wrappers** that internally use scoped `with_secret` access — they do **not** bypass the security model, but return the fully materialized encoded value.

They exist because users who call them have already decided to reveal the secret — the wrapper reduces boilerplate and avoids long-lived raw references.

Every encoder returns [`EncodedSecret`] (wrapping `Zeroizing<String>` with a redacted `Debug` and no `Display`), so encoded output is wiped on drop by default.

**Audit every exposure point** by searching your codebase for:

- **Access:** `expose_secret`, `expose_secret_mut`, `with_secret`, `with_secret_mut`
- **Extract:** `into_inner` (hands the plain secret to the caller; protection ends), `as_reader` (yields a reader over the secret bytes)
- **Encode:** `to_hex`, `to_hex_upper`, `to_base32`, `to_base64url`, `try_to_bech32`, `try_to_bech32m`, and their `_sized::<N>` forms — all returning `EncodedSecret`
- **Decode:** `try_from_hex`, `try_from_base32`, `try_from_base64url`, `try_from_bech32*` (including `_unchecked`)

**Best practice**: Prefer scoped methods (`with_secret` / `with_secret_mut`) when possible — they keep exposure minimal.

## What changed in 0.9.0

Edition 2024, MSRV 1.85, `rand` 0.10 (`OsRng` → `SysRng`), dep bumps.  
Across the release candidates: `SecretLen` split out of `RevealSecret` (which now covers
every inner type); Base32 (RFC 4648 §6) added behind `encoding-base32`; wrapper encoders
are `ToHex` / `ToBase32` / `ToBase64Url` / `ToBech32` / `ToBech32m` trait impls; `fixed_newtype!` / `dynamic_newtype!` for nominal secret roles; no `Display`
on `EncodedSecret`.

Two breaking changes are worth reading before you upgrade. Every encoder now returns
`EncodedSecret` and the `*_zeroizing` twins are gone, so the short name is the safe one.
And `into_inner` returns the plain value rather than a wrapper that kept wiping —
**protection now ends at that call**, where earlier release candidates continued it.  
Full details in [CHANGELOG.md](CHANGELOG.md). Users on Rust < 1.85: pin `secure-gate = "0.8"`.

## Branch support

| Branch | Version | Rust edition | MSRV | Status |
|---|---|---|---|---|
| `main` | 0.9.x | 2024 | 1.85 | Active development |
| `release/0.8` | 0.8.x | 2021 | 1.70 | LTS — security patches only |

**Rust ≥ 1.85**: use `secure-gate = "0.9"`.  
**Rust < 1.85**: pin `secure-gate = "0.8"`.

Security fixes and important bug fixes may be backported from `main` to `release/0.8` as
patch releases. The 0.8 line will receive patches for as long as the dependencies it
relies on remain compatible with Rust 1.70.

## Migrating from secrecy

The `secure-gate-compat` shim crate, which provided drop-in replacements for `secrecy`
v0.8 and v0.10, has been removed. It was experimental and never published. If you need
it, it is recoverable from git history — `git checkout v0.9.0-rc.9 -- secure-gate-compat`
restores the last version, along with its migration guide.

## Features

Common stacks: default (`alloc`), `features = ["full"]`, or `default-features = false` for heap-free `Fixed` only.

| Feature             | Description                                                                                                                                                                                                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `alloc` _(default)_ | Heap-allocated `Dynamic<T>` + full zeroization of `Vec`/`String` spare capacity                                                                                                                                                                           |
| `std`               | Full `std` support (implies `alloc`). Enables `std::io::Read`/`Write` for `Dynamic<Vec<u8>>` via `as_reader()` and direct `Write` impl. Use `default-features = false` for no-heap builds. |
| `rand`              | `from_random()` (system `SysRng`) and fallible `from_rng()` for any `TryRng + TryCryptoRng`; `no_std` compatible for `Fixed<T>` (no heap required). `Dynamic::from_random()` / `from_rng()` require `alloc` (implicit — `Dynamic<T>` itself requires it). |
| `ct-eq`             | `ConstantTimeEq` — timing-safe comparison via `expose_secret()` (`subtle`)                                                                                                                                                                                |
| `encoding`          | Meta: all encoding sub-features (hex, base32, base64url, bech32). Encoding traits require `alloc`; `Fixed::try_from_*` decoding is no-alloc.                                                                                                     |
| `encoding-hex`      | `ToHex` / `FromHexStr` — constant-time via `base16ct`                                                                                                                                                                                                     |
| `encoding-base32`   | `ToBase32` / `FromBase32Str` — constant-time via `base32ct`; RFC 4648 §6, uppercase and unpadded                                                                                                                                                          |
| `encoding-base64`   | `ToBase64Url` / `FromBase64UrlStr` — constant-time via `base64ct`                                                                                                                                                                                         |
| `encoding-bech32`   | BIP-173 (`ToBech32` / `FromBech32Str`) **and** BIP-350 (`ToBech32m` / `FromBech32mStr`). One feature: the two are the same code, one checksum constant apart. `_sized::<N>` on every method sets the code length.                                          |
| `serde`             | Meta: `serde-deserialize` + `serde-serialize`                                                                                                                                                                                                             |
| `serde-deserialize` | Direct deserialization; `Zeroizing`-wrapped buffers; 1 MiB default limit (`MAX_DESERIALIZE_BYTES`); use `deserialize_with_limit` for custom ceilings                                                                                                      |
| `serde-serialize`   | Serialize secrets (requires `SerializableSecret` marker on inner type)                                                                                                                                                                                    |
| `cloneable`         | `CloneableSecret` opt-in cloning                                                                                                                                                                                                                          |
| `full`              | All features except `std`                                                                                                                                                                                                                                   |

`no_std` compatible — the crate is `#![no_std]` unless the `std` feature is enabled, verified in CI by cross-building for `thumbv7em-none-eabihf`. `Fixed<T>` with `rand` works heap-free (on bare-metal targets, `getrandom` additionally requires a user-configured platform backend for `from_random`; `from_rng` with a caller-supplied RNG has no such requirement). `Dynamic<T>`, encoding traits, and serde require `alloc`. `Fixed::try_from_*` decoding works without `alloc` using constant-time stack-based decoders. Disabled features have zero overhead.

## Contributing

### MSRV & Lockfile

This crate (`main`, 0.9.x) enforces MSRV 1.85 (`rust-version = "1.85"` in `Cargo.toml`). Rust 1.85 is the minimum that supports **Rust edition 2024**.

Always use the MSRV toolchain to update `Cargo.lock`:

```bash
cargo +1.85 update
git add Cargo.lock
git commit -m "chore: regenerate Cargo.lock with MSRV 1.85"
```

## CI

The CI pipeline (`main` branch) runs lint, test (19 feature combinations), rustdoc, MSRV (1.85), AddressSanitizer heap verification, and libFuzzer/Miri targets. See [`.github/workflows/`](.github/workflows/).

The `rustdoc` job builds with `--all-features`, matching `[package.metadata.docs.rs]`: **the docs.rs feature set is the enforced documentation contract.** Intra-doc links that only break in minimal builds (`alloc` alone, for instance) are best-effort and deliberately not fixed — see [#175](https://github.com/Slurp9187/secure-gate/issues/175).

## License

MIT OR Apache-2.0
