# secure-gate

[![Crates.io](https://img.shields.io/crates/v/secure-gate.svg)](https://crates.io/crates/secure-gate)
[![Docs.rs](https://docs.rs/secure-gate/badge.svg)](https://docs.rs/secure-gate)
[![CI](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml)
[![MSRV: 1.85](https://img.shields.io/badge/msrv-1.85-blue)](https://github.com/Slurp9187/secure-gate/blob/main/Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

A `no_std`-compatible, zero-overhead library for managing secrets with mandatory zeroization and audit-friendly access patterns.

> **Security Notice**: This crate has **not undergone independent audit**.
> Review the code and [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) before production use.
> No unsafe code — enforced with `#![forbid(unsafe_code)]`.

## Quick Start

```rust
use secure_gate::{dynamic_alias, fixed_alias, RevealSecret, RevealSecretMut};

dynamic_alias!(pub Password, String);    // Dynamic<String>
fixed_alias!(pub Aes256Key, 32);         // Fixed<[u8; 32]>

let mut pw: Password = "hunter2".into();
let key: Aes256Key = Aes256Key::new([42u8; 32]);

// Scoped access — preferred; the borrow cannot outlive the closure
pw.with_secret(|s| println!("length: {}", s.len()));

// Mutable scoped access
pw.with_secret_mut(|s: &mut String| s.push('!'));

// Direct reference — auditable escape hatch (e.g. FFI, third-party APIs)
assert_eq!(pw.expose_secret(), "hunter2!");
pw.expose_secret_mut().clear();

#[cfg(all(feature = "encoding-hex", feature = "encoding-bech32"))]
{
    use secure_gate::{Fixed, RevealSecret, ToHex, ToBech32, FromHexStr};

    let key: Fixed<[u8; 32]> = Fixed::new([42u8; 32]);

    // Encode to hex (scoped borrow — no long-lived reference)
    let hex: String = key.with_secret(|bytes| bytes.to_hex());

    // Encode to Bech32 (BIP-173) with human-readable prefix "key"
    let bech32: String = key.with_secret(|bytes| {
        bytes.try_to_bech32("key").expect("valid bech32")
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
- `.len()` / `.is_empty()` without exposure
- Zeroize on drop (always)
- Access via `.with_secret(|s| ...)` (preferred) or `.expose_secret()` (auditable escape hatch)

### Preferred: scoped access

```rust
use secure_gate::{Fixed, RevealSecret, RevealSecretMut};

let mut key: Fixed<[u8; 32]> = Fixed::new([0xAB; 32]);

// Read — closure borrow cannot outlive the call
let sum: u32 = key.with_secret(|bytes| bytes.iter().map(|&b| b as u32).sum());

// Mutate
key.with_secret_mut(|bytes: &mut [u8; 32]| bytes[0] = 0);
```

### Direct reference — auditable escape hatch

```rust
// Use only when a long-lived reference is unavoidable (FFI, third-party APIs)
use secure_gate::{Fixed, RevealSecret};
let key: Fixed<[u8; 32]> = Fixed::new([0xAB; 32]);
let raw: &[u8; 32] = key.expose_secret();
```

### Macros for typed aliases

`fixed_alias!`, `dynamic_alias!`, `fixed_generic_alias!`, and `dynamic_generic_alias!` create typed newtype wrappers with full visibility control, optional doc strings, and compile-time zero-size guards:

```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub Aes256Key, 32, "32-byte AES-256 key");

#[cfg(feature = "alloc")]
dynamic_alias!(pub Password, String, "variable-length password");
```

See [`fixed_alias!`], [`dynamic_alias!`], [`fixed_generic_alias!`], and [`dynamic_generic_alias!`] in the [API docs](https://docs.rs/secure-gate).

**Zero-size behavior note**  
`fixed_alias!(Name, N)` rejects `N = 0` at compile time (via a const-eval index-out-of-bounds guard).  
However, `fixed_generic_alias!`, `dynamic_alias!`, and `dynamic_generic_alias!` **allow** zero-sized types (`SecretBuffer<0>`, `Dynamic<[u8; 0]>`, `Dynamic<()>` etc.). These compile successfully but have no cryptographic value and should never be used in production. Always validate that the effective size is > 0 in your unit tests when using the generic or dynamic alias macros.

See also the Best Practices section in [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for the equivalent guidance.

### Polymorphic / generic code

```rust
use secure_gate::RevealSecret;

fn log_length<S: RevealSecret>(secret: &S) {
    println!("length = {}", secret.len());
}
```

## What You Get

- **Zero-cost safety** — mandatory zeroization on drop; `no_std` / `no_alloc` support. See [ZERO_COST_WRAPPERS.md](https://github.com/Slurp9187/secure-gate/blob/main/ZERO_COST_WRAPPERS.md) for benchmarks.
- **Audit-first API** — secrets cannot leak via `Deref`. Access requires explicit `with_secret` scopes or an auditable `expose_secret` escape hatch.
- **Type-safe wrappers** — macros create newtype aliases that redact `Debug` output automatically.
- **Batteries included** — optional, zero-overhead support for serde, constant-time comparison (`subtle`), and secure encoding (hex, base64url, bech32/m).
- **No unsafe code** — enforced with `#![forbid(unsafe_code)]`.

## Installation

**Default** (`alloc` enabled — `Fixed<T>` + `Dynamic<T>` + full zeroization):

```toml
[dependencies]
secure-gate = "0.9.0-rc.2"
```

**No-heap / embedded** (`Fixed<T>` only — pure stack / `no_std`):

```toml
secure-gate = { version = "0.9.0-rc.2", default-features = false }
```

**Batteries-included**:

```toml
secure-gate = { version = "0.9.0-rc.2", features = ["full"] }
```

## Encoding & Decoding

`secure-gate` provides symmetric, zero-overhead encoding and decoding for four formats: hex, base64url, bech32 (BIP-173), and bech32m (BIP-350). All operations are explicit and return `Result` on failure.

### Available traits

| Format            | Encode        | Decode             | Feature            |
| ----------------- | ------------- | ------------------ | ------------------ |
| Hex               | `ToHex`       | `FromHexStr`       | `encoding-hex`     |
| Base64URL         | `ToBase64Url` | `FromBase64UrlStr` | `encoding-base64`  |
| Bech32 (BIP-173)  | `ToBech32`    | `FromBech32Str`    | `encoding-bech32`  |
| Bech32m (BIP-350) | `ToBech32m`   | `FromBech32mStr`   | `encoding-bech32m` |

### Encoding (to string)

Use trait methods on the wrapper:

```rust
let key: Fixed<[u8; 32]> = ...;

// Direct on the wrapper (convenient; omit `with_secret` from audit greps)
let hex = key.to_hex();
let b64 = key.to_base64url();
let bech32 = key.try_to_bech32("bc")?;
let bech32m = key.try_to_bech32m("bc")?;

// Scoped on the inner bytes (preferred when you want `with_secret` in audit sweeps)
let hex_scoped = key.with_secret(|s| s.to_hex());
let b64_scoped = key.with_secret(|s| s.to_base64url());
let bech32_scoped = key.with_secret(|s| s.try_to_bech32("bc"))?;
let bech32m_scoped = key.with_secret(|s| s.try_to_bech32m("bc"))?;
```

### Direct Constructors (Recommended)

Both `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` offer the same one-shot constructors from strings (call `Fixed::…` or `Dynamic::…` depending on which wrapper you need). These use panic-safe `Zeroizing` + pre-alloc swap internally.

| Format              | Method (both wrappers)              | Notes                                       |
| ------------------- | ----------------------------------- | ------------------------------------------- |
| Hex                 | `try_from_hex(s)`                   | `HexError`                                  |
| Base64URL           | `try_from_base64url(s)`             | `Base64Error` (unpadded, URL-safe)          |
| Bech32 (BIP-173)    | `try_from_bech32(s, hrp)`           | HRP validated; `Bech32Error::UnexpectedHrp` |
| Bech32 (unchecked)  | `try_from_bech32_unchecked(s)`      | No HRP; `Bech32Error`                       |
| Bech32m (BIP-350)   | `try_from_bech32m(s, hrp)`          | HRP validated; `Bech32Error::UnexpectedHrp` |
| Bech32m (unchecked) | `try_from_bech32m_unchecked(s)`     | No HRP; `Bech32Error`                       |

**Security notes**:

- Prefer HRP-validated constructors to prevent cross-protocol confusion attacks.
- Use `_unchecked` only when HRP is validated upstream.
- All constructors guarantee zeroization even on OOM panic via `Zeroizing`.

## Serde

`serde-deserialize` decodes directly to the inner type. After deserialization completes, temporary buffers for `Dynamic<Vec<u8>>` and `Dynamic<String>` are `Zeroizing`-wrapped — oversized buffers are zeroized even on rejection. The default limit is `MAX_DESERIALIZE_BYTES` (1 MiB); call `Dynamic::deserialize_with_limit` to set a custom ceiling. Serialization requires the `SerializableSecret` marker trait.

> **Note:** `MAX_DESERIALIZE_BYTES` (and `deserialize_with_limit`) is enforced _after_ the upstream deserializer has fully materialized the payload. It is a result-length acceptance bound, not a pre-allocation DoS guard. For untrusted input, enforce size limits at the transport or parser layer upstream.

See [`SerializableSecret`] in the [API docs](https://docs.rs/secure-gate) for the full example.

## Random Generation

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::Fixed;
    let key: Fixed<[u8; 32]> = Fixed::from_random();
}
```

Cryptographically secure via `SysRng`. `Fixed::from_random()` is heap-free and works in `no_std`/`no_alloc` builds. `Dynamic::from_random()` requires `alloc` (implicit — `Dynamic<T>` itself already requires it). See [`Fixed::from_random`] and [`Dynamic::from_random`] in the [API docs](https://docs.rs/secure-gate).

## Audit Guide

Encoding and decoding methods are **convenience wrappers** that internally use scoped `with_secret` access — they do **not** bypass the security model, but return the fully materialized encoded value.

They exist because users who call them have already decided to reveal the secret — the wrapper reduces boilerplate and avoids long-lived raw references.

**Audit every exposure point** by searching your codebase for:

- **Access:** `expose_secret`, `expose_secret_mut`, `with_secret`, `with_secret_mut`
- **Encode:** `to_hex`, `to_base64url`, `try_to_bech32`, `try_to_bech32m`
- **Decode:** `try_from_hex`, `try_from_base64url`, `try_from_bech32*` (including `_unchecked`)

**Best practice**: Prefer scoped methods (`with_secret` / `with_secret_mut`) when possible — they keep exposure minimal.

Read [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for the full threat model and mitigations.

## What changed in 0.9.0

Edition 2024, MSRV 1.85, `rand` 0.10 (`OsRng` → `SysRng`), dep bumps.  
Full details in [CHANGELOG.md](CHANGELOG.md). Users on Rust < 1.85: pin `secure-gate = "0.8"`.

## Branch support

Version **0.9.x** (`main`) targets Rust Edition 2024 and MSRV 1.85.  
For Rust < 1.85, pin `secure-gate = "0.8"` — the `release/0.8` branch (Edition 2021, MSRV 1.75) receives security patches and important backports.

Current crates.io version: 0.9.0-rc.2 (see [Cargo.toml](https://github.com/Slurp9187/secure-gate/blob/main/Cargo.toml) for exact version).

## Features

Common stacks: default (`alloc`), `features = ["full"]`, or `default-features = false` for heap-free `Fixed` only.

| Feature             | Description                                                                                                                                                                  |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `alloc` _(default)_ | Heap-allocated `Dynamic<T>` + full zeroization of `Vec`/`String` spare capacity                                                                                              |
| `std`               | Full `std` support (implies `alloc`). Use `default-features = false` for no-heap builds.                                                                                     |
| `rand`              | `from_random()` via `SysRng`; `no_std` compatible for `Fixed<T>` (no heap required). `Dynamic::from_random()` requires `alloc` (implicit — `Dynamic<T>` itself requires it). |
| `ct-eq`             | `ConstantTimeEq` — timing-safe direct byte comparison (`subtle`)                                                                                                             |
| `encoding`          | Meta: all encoding sub-features (hex, base64url, bech32, bech32m); requires `alloc`                                                                                          |
| `encoding-hex`      | `ToHex` / `FromHexStr`                                                                                                                                                       |
| `encoding-base64`   | `ToBase64Url` / `FromBase64UrlStr`                                                                                                                                           |
| `encoding-bech32`   | `ToBech32` / `FromBech32Str` — BIP-173                                                                                                                                       |
| `encoding-bech32m`  | `ToBech32m` / `FromBech32mStr` — BIP-350                                                                                                                                     |
| `serde`             | Meta: `serde-deserialize` + `serde-serialize`                                                                                                                                |
| `serde-deserialize` | Direct deserialization; `Zeroizing`-wrapped buffers; 1 MiB default limit (`MAX_DESERIALIZE_BYTES`); use `deserialize_with_limit` for custom ceilings                         |
| `serde-serialize`   | Serialize secrets (requires `SerializableSecret` marker on inner type)                                                                                                       |
| `cloneable`         | `CloneableSecret` opt-in cloning                                                                                                                                             |
| `full`              | All features combined                                                                                                                                                        |

`no_std` compatible. `Fixed<T>` with `rand` works heap-free. `Dynamic<T>`, encoding, and serde require `alloc`. Disabled features have zero overhead.

## Contributing

### MSRV & Lockfile

This crate (`main`, 0.9.x) enforces MSRV 1.85 (`rust-version = "1.85"` in `Cargo.toml`). Rust 1.85 is the minimum that supports **Rust edition 2024**.

Always use the MSRV toolchain to update `Cargo.lock`:

```bash
cargo +1.85 update
git add Cargo.lock
git commit -m "chore: regenerate Cargo.lock with MSRV 1.85"
```

## License

MIT OR Apache-2.0
