# secure-gate

[![Crates.io](https://img.shields.io/crates/v/secure-gate.svg)](https://crates.io/crates/secure-gate)
[![Docs.rs](https://docs.rs/secure-gate/badge.svg)](https://docs.rs/secure-gate)
[![CI](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

Current crates.io version: 0.9.0-rc.1 (see `Cargo.toml` for exact version).

`no_std`-compatible secret wrappers with explicit, auditable access and **mandatory zeroization on drop**.

> **Security Notice**: This crate has **not undergone independent audit**.
> Review the code and [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) before production use.
> No unsafe code — enforced with `#![forbid(unsafe_code)]`.

## What changed in 0.8.0

- **Zeroize is now mandatory** — memory wiping on drop is always enabled with no feature gate.
- `Fixed<T>` requires `T: Zeroize`; `Dynamic<T>` requires `T: ?Sized + Zeroize`.
- Removed the old optional `zeroize` feature and related toggles (`insecure`, `secure`, and `std`).
- Real `impl Drop` now calls `zeroize()` on the inner value — the documented zeroization guarantee is fully enforced.
- All previous versions (0.1.0–0.7.0-rc.15) were yanked from crates.io.
- Greatly expanded zeroization test suite with multi-size coverage, spare-capacity checks for both `Vec` and `String`, runtime heap verification via `ProxyAllocator`, and AddressSanitizer integration.

## What You Get

- **Explicit access only** — `.with_secret()` (preferred) or `.expose_secret()` required; no silent `Deref`/`AsRef` leaks
- **Mandatory zeroize on drop** — always active, no feature gate (inner type must implement `Zeroize`)
- **Timing-safe equality** — `ct-eq` feature for deterministic constant-time byte comparison (`subtle`)
- **Secure random generation** — `from_random()` via `OsRng` (`rand` feature)
- **Orthogonal encoding** — symmetric per-format traits + direct `try_from_*` constructors on `Fixed` and `Dynamic<Vec<u8>>` (hex, base64url, bech32/BIP-173, bech32m/BIP-350); each format is opt-in and zero-overhead when unused
- **Serde** — direct deserialization to inner types (binary-safe); opt-in serialization requires `SerializableSecret` marker
- **Ergonomic aliases** — `dynamic_alias!`, `fixed_alias!`, `fixed_generic_alias!`, `dynamic_generic_alias!` for typed newtypes
- **Auditable** — every secret exposure point (including encoding methods) is grep-able using the consolidated pattern shown in the [Encoding](#encoding) section; `no_std` + `alloc` compatible

For zero-cost performance justification see [ZERO_COST_WRAPPERS.md](https://github.com/Slurp9187/secure-gate/blob/main/ZERO_COST_WRAPPERS.md).

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

## Installation

**Default** (`alloc` enabled — `Fixed<T>` + `Dynamic<T>` + full zeroization):

```toml
[dependencies]
secure-gate = "0.8.0-rc.1"
```

**No-heap / embedded** (`Fixed<T>` only — pure stack / `no_std`):

```toml
secure-gate = { version = "0.8.0-rc.1", default-features = false }
```

**Batteries-included**:

```toml
secure-gate = { version = "0.8.0-rc.1", features = ["full"] }
```

## Features

| Feature             | Description                                                                                                                                                                 |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `alloc` _(default)_ | Heap-allocated `Dynamic<T>` + full zeroization of `Vec`/`String` spare capacity                                                                                             |
| `std`               | Full `std` support (implies `alloc`). Use `default-features = false` for no-heap builds.                                                                                    |
| `rand`              | `from_random()` via `OsRng`; `no_std` compatible for `Fixed<T>` (no heap required). `Dynamic::from_random()` requires `alloc` (implicit — `Dynamic<T>` itself requires it). |
| `ct-eq`             | `ConstantTimeEq` — timing-safe direct byte comparison (`subtle`)                                                                                                            |
| `encoding`          | Meta: all encoding sub-features (hex, base64url, bech32, bech32m); requires `alloc`                                                                                         |
| `encoding-hex`      | `ToHex` / `FromHexStr`                                                                                                                                                      |
| `encoding-base64`   | `ToBase64Url` / `FromBase64UrlStr`                                                                                                                                          |
| `encoding-bech32`   | `ToBech32` / `FromBech32Str` — BIP-173                                                                                                                                      |
| `encoding-bech32m`  | `ToBech32m` / `FromBech32mStr` — BIP-350                                                                                                                                    |
| `serde`             | Meta: `serde-deserialize` + `serde-serialize`                                                                                                                               |
| `serde-deserialize` | Direct deserialization; `Zeroizing`-wrapped buffers; 1 MiB default limit (`MAX_DESERIALIZE_BYTES`); use `deserialize_with_limit` for custom ceilings                        |
| `serde-serialize`   | Serialize secrets (requires `SerializableSecret` marker on inner type)                                                                                                      |
| `cloneable`         | `CloneableSecret` opt-in cloning                                                                                                                                            |
| `full`              | All features combined                                                                                                                                                       |

`no_std` compatible. `Fixed<T>` with `rand` works heap-free. `Dynamic<T>`, encoding, and serde require `alloc`. Disabled features have zero overhead.

## Core API

`Fixed<T>` (stack-allocated) and `Dynamic<T>` (heap-allocated, requires `alloc`) share the same `RevealSecret` / `RevealSecretMut` interface. Both types:

- Redact `Debug` output to `[REDACTED]`
- Implement `len()` and `is_empty()` without exposing secret contents
- Zeroize contents on drop (mandatory)

The preferred and recommended way to access secrets is the scoped `with_secret` / `with_secret_mut` methods. `expose_secret` / `expose_secret_mut` are escape hatches for rare cases and should be audited closely.

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

let hex    = key.to_hex();             // String
let b64    = key.to_base64url();       // String
let bech32 = key.try_to_bech32("bc")?; // String with HRP
let bech32m = key.try_to_bech32m("bc")?; // String with HRP
```

### Direct Constructors (Recommended)

Both `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` offer one-shot constructors from strings. These use panic-safe `Zeroizing` + pre-alloc swap internally.

| Format              | `Fixed<[u8; N]>`                       | `Dynamic<Vec<u8>>`                       | Notes                                       |
| ------------------- | -------------------------------------- | ---------------------------------------- | ------------------------------------------- |
| Hex                 | `Fixed::try_from_hex(s)`               | `Dynamic::try_from_hex(s)`               | `HexError`                                  |
| Base64URL           | `Fixed::try_from_base64url(s)`         | `Dynamic::try_from_base64url(s)`         | `Base64Error` (unpadded, URL-safe)          |
| Bech32 (BIP-173)    | `Fixed::try_from_bech32(s, hrp)`       | `Dynamic::try_from_bech32(s, hrp)`       | HRP validated; `Bech32Error::UnexpectedHrp` |
| Bech32 (unchecked)  | `Fixed::try_from_bech32_unchecked(s)`  | `Dynamic::try_from_bech32_unchecked(s)`  | No HRP; `Bech32Error`                       |
| Bech32m (BIP-350)   | `Fixed::try_from_bech32m(s, hrp)`      | `Dynamic::try_from_bech32m(s, hrp)`      | HRP validated; `Bech32Error::UnexpectedHrp` |
| Bech32m (unchecked) | `Fixed::try_from_bech32m_unchecked(s)` | `Dynamic::try_from_bech32m_unchecked(s)` | No HRP; `Bech32Error`                       |

**Security notes**:

- Prefer HRP-validated constructors to prevent cross-protocol confusion attacks.
- Use `_unchecked` only when HRP is validated upstream.
- All constructors guarantee zeroization even on OOM panic via `Zeroizing`.

### Audit Surface (All Secret Materialization)

All encoding and direct decoding bypass `expose_secret` / `with_secret`. Audit with project-wide search (`rg`, IDE “find in files”) for **every** name below:

- **Access:** `expose_secret`, `expose_secret_mut`, `with_secret`, `with_secret_mut`
- **Encode:** `to_hex`, `to_base64url`, `try_to_bech32`, `try_to_bech32m`
- **Decode:** `try_from_hex`, `try_from_base64url`, `try_from_bech32`, `try_from_bech32m`

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

Cryptographically secure via `OsRng`. `Fixed::from_random()` is heap-free and works in `no_std`/`no_alloc` builds. `Dynamic::from_random()` requires `alloc` (implicit — `Dynamic<T>` itself already requires it). See [`Fixed::from_random`] and [`Dynamic::from_random`] in the [API docs](https://docs.rs/secure-gate).

## Security Model

- **Explicit access only** — `.with_secret()` / `.expose_secret()` required; no silent leaks
- **Zeroize on drop** — always active; inner type must implement `Zeroize`
- **Timing-safe equality** — `ct-eq` feature (`.ct_eq()`)
- **No unsafe code** — enforced with `#![forbid(unsafe_code)]`

Read [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for the full threat model and mitigations.

## Contributing

### MSRV & Lockfile

This crate (`main`, 0.9.x) enforces MSRV 1.85 (`rust-version = "1.85"` in `Cargo.toml`). Rust 1.85 is the minimum that supports **Rust edition 2024**.

Always use the MSRV toolchain to update `Cargo.lock`:

```bash
cargo +1.85 update
git add Cargo.lock
git commit -m "chore: regenerate Cargo.lock with MSRV 1.85"
```

### Dual-track support

| Branch | Crate version | Rust edition | MSRV | Status |
|---|---|---|---|---|
| `main` | 0.9.x | 2024 | 1.85 | Active development |
| `release/0.8` | 0.8.x | 2021 | 1.75 | LTS — security patches only |

**Users on Rust < 1.85:** pin `secure-gate = "0.8"` in `Cargo.toml`. The `release/0.8` branch is maintained for security patches and important bug fixes backported from `main`.

## License

MIT OR Apache-2.0
