# secure-gate

[![Crates.io](https://img.shields.io/crates/v/secure-gate.svg)](https://crates.io/crates/secure-gate)
[![Docs.rs](https://docs.rs/secure-gate/badge.svg)](https://docs.rs/secure-gate)
[![CI](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

**0.8.0 — reboot release after critical zeroize bug fix. All prior versions yanked from crates.io.**

`no_std`-compatible secret wrappers with explicit, auditable access and **mandatory zeroization on drop**.

> **Security Notice**: This crate has **not undergone independent audit**.
> Review the code and [SECURITY.md](SECURITY.md) before production use.
> No unsafe code — enforced with `#![forbid(unsafe_code)]`.

## What changed in 0.8.0

- **Zeroize is now mandatory** — memory wiping on drop is always enabled, no feature gate.
- `Fixed<T>` requires `T: Zeroize`; `Dynamic<T>` requires `T: ?Sized + Zeroize`.
- Removed `zeroize`, `insecure`, `secure`, and `std` feature toggles.
- Real `impl Drop` now calls `zeroize()` — the original security promise is finally true.

- **All versions 0.1.0–0.7.0-rc.15 were yanked** from crates.io due to a critical zeroize-on-drop flaw that has now been fixed.

- **Zeroization test suite greatly expanded** — multi-size coverage, spare-capacity checks for both Vec and String, runtime heap-byte verification via ProxyAllocator, and AddressSanitizer integration.

## What You Get

- **Explicit access only** — `.with_secret()` (preferred) or `.expose_secret()` required; no silent `Deref`/`AsRef` leaks
- **Mandatory zeroize on drop** — always active, no feature gate (inner type must implement `Zeroize`)
- **Timing-safe equality** — `ct-eq` feature for deterministic constant-time byte comparison (`subtle`)
- **Secure random generation** — `from_random()` via `OsRng` (`rand` feature)
- **Orthogonal encoding** — symmetric per-format traits (hex, base64url, bech32/BIP-173, bech32m/BIP-350); each format is opt-in and zero-overhead when unused
- **Serde** — direct deserialization to inner types (binary-safe); opt-in serialization requires `SerializableSecret` marker
- **Ergonomic aliases** — `dynamic_alias!`, `fixed_alias!`, `fixed_generic_alias!`, `dynamic_generic_alias!` for typed newtypes
- **Auditable** — every exposure, encoding, and equality call is grep-able; `no_std` + `alloc` compatible

For zero-cost performance justification see [ZERO_COST_WRAPPERS.md](ZERO_COST_WRAPPERS.md).

## Quick Start

```rust
use secure_gate::{dynamic_alias, fixed_alias, ExposeSecret, ExposeSecretMut};

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
    use secure_gate::{Fixed, ExposeSecret, ToHex, ToBech32, FromHexStr};

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

| Feature             | Description                                                                                                                                          |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `alloc` _(default)_ | Heap-allocated `Dynamic<T>` + full zeroization of `Vec`/`String` spare capacity                                                                      |
| `std`               | Full `std` support (implies `alloc`). Use `default-features = false` for no-heap builds.                                                             |
| `rand`              | `from_random()` via `OsRng`; `no_std` compatible for `Fixed<T>` (no heap required). `Dynamic::from_random()` requires `alloc` (implicit — `Dynamic<T>` itself requires it).    |
| `ct-eq`             | `ConstantTimeEq` — timing-safe direct byte comparison (`subtle`)                                                                                     |
| `encoding`          | Meta: all encoding sub-features (hex, base64url, bech32, bech32m); requires `alloc`                                                                  |
| `encoding-hex`      | `ToHex` / `FromHexStr`                                                                                                                               |
| `encoding-base64`   | `ToBase64Url` / `FromBase64UrlStr`                                                                                                                   |
| `encoding-bech32`   | `ToBech32` / `FromBech32Str` — BIP-173                                                                                                               |
| `encoding-bech32m`  | `ToBech32m` / `FromBech32mStr` — BIP-350                                                                                                             |
| `serde`             | Meta: `serde-deserialize` + `serde-serialize`                                                                                                        |
| `serde-deserialize` | Direct deserialization; `Zeroizing`-wrapped buffers; 1 MiB default limit (`MAX_DESERIALIZE_BYTES`); use `deserialize_with_limit` for custom ceilings |
| `serde-serialize`   | Serialize secrets (requires `SerializableSecret` marker on inner type)                                                                               |
| `cloneable`         | `CloneableSecret` opt-in cloning                                                                                                                     |
| `full`              | All features combined                                                                                                                                |

`no_std` compatible. `Fixed<T>` with `rand` works heap-free. `Dynamic<T>`, encoding, and serde require `alloc`. Disabled features have zero overhead.

## Core API

`Fixed<T>` (stack-allocated) and `Dynamic<T>` (heap-allocated, requires `alloc`) share the same `ExposeSecret` / `ExposeSecretMut` interface. Both types:

- Redact `Debug` output to `[REDACTED]`
- Implement `len()` and `is_empty()` without exposing secret contents
- Zeroize contents on drop (mandatory)

### Preferred: scoped access

```rust
use secure_gate::{Fixed, ExposeSecret, ExposeSecretMut};

let mut key: Fixed<[u8; 32]> = Fixed::new([0xAB; 32]);

// Read — closure borrow cannot outlive the call
let sum: u32 = key.with_secret(|bytes| bytes.iter().map(|&b| b as u32).sum());

// Mutate
key.with_secret_mut(|bytes: &mut [u8; 32]| bytes[0] = 0);
```

### Direct reference — auditable escape hatch

```rust
// Use only when a long-lived reference is unavoidable (FFI, third-party APIs)
use secure_gate::{Fixed, ExposeSecret};
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

### Polymorphic / generic code

```rust
use secure_gate::ExposeSecret;

fn log_length<S: ExposeSecret>(secret: &S) {
    println!("length = {}", secret.len());
}
```

## Encoding

`secure-gate` provides orthogonal, zero-overhead encoding traits for the most common formats. Encoding is **not** a bypass of the exposure rules — it is deliberate, auditable secret exposure with three access patterns:

- **Direct method (`key.to_hex()`)** — ergonomically safest for single operations. No reference in the caller's hands; exposure is entirely internal. Does not appear in `grep expose_secret` / `grep with_secret` sweeps.
- **`with_secret` closure** — best for multi-step operations and audit-first teams. Borrow checker enforces the reference cannot escape the closure. Appears in `grep with_secret` sweeps.
- **`expose_secret` + encode** — escape hatch for FFI or third-party APIs requiring `&[u8]`. Chaining immediately is safe; binding to a named variable that outlives the call is the danger.

**Never treat encoded output as non-sensitive** — it contains the entire secret.

Available methods (`E` = encode on bytes/wrapper, `D` = decode from string):

- **Hex** (`encoding-hex`) — E: `to_hex()`, `to_hex_upper()` · D: `"…".try_from_hex()` → `Vec<u8>`
- **Base64URL** (`encoding-base64`) — E: `to_base64url()` · D: `"…".try_from_base64url()` → `Vec<u8>`
- **Bech32 BIP-173** (`encoding-bech32`) — E: `try_to_bech32(hrp)` · D (validated): `"…".try_from_bech32(hrp)` → `Vec<u8>` · D (unchecked): `"…".try_from_bech32_unchecked()` → `(String, Vec<u8>)` · D (wrapped): `Fixed::try_from_bech32(s, hrp)`, `Dynamic::try_from_bech32(s, hrp)` — prefer these over `try_from_bech32_unchecked`
- **Bech32m BIP-350** (`encoding-bech32m`) — E: `try_to_bech32m(hrp)` · D (validated): `"…".try_from_bech32m(hrp)` · D (unchecked): `"…".try_from_bech32m_unchecked()` · D (wrapped): `Fixed::try_from_bech32m(s, hrp)`, `Dynamic::try_from_bech32m(s, hrp)` — prefer validated over `try_from_bech32m_unchecked`

### Patterns

**Direct convenience method — ergonomically safest for single operations**

No reference in the caller's hands; the exposure is entirely internal and cannot be misused. Recommended for the common single-encode case.

```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::{Fixed, ToHex};
    let key = Fixed::new([0u8; 32]);
    let hex: String = key.to_hex();
}
```

> **Audit note**: Direct calls do not appear in `grep expose_secret` or `grep with_secret` sweeps — see the consolidated grep command at the end of this section.

**`with_secret` closure — best for multi-step operations and audit-first teams**

The borrow checker enforces that the inner reference cannot escape the closure. Preferred when the inner bytes are needed for more than one operation; shows up in `grep with_secret` sweeps.

```rust
#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::{Fixed, ToBech32, ExposeSecret};
    let key = Fixed::new([0u8; 32]);
    // Encode and decode in the same scoped access
    let encoded = key.with_secret(|b| b.try_to_bech32("key")).unwrap();
}
```

**Manual `expose_secret` + encode — escape hatch only**

Chaining immediately (`key.expose_secret().to_hex()`) is safe — the reference is dropped at the semicolon. The danger is binding to a named variable:

```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::{Fixed, ExposeSecret, ToHex};
    let key = Fixed::new([0u8; 32]);
    // Dangerous: reference outlives the encoding call
    let bytes = key.expose_secret();
    // ... bytes can now be passed to other fns, stored in structs, etc. ...
    let hex = bytes.to_hex();
}
```

Use only when inner bytes must be passed to code that does not know about `secure-gate` (FFI, third-party APIs taking `&[u8]` directly). Keep the binding as short-lived as possible.

### Bech32 decoding — prefer HRP-validated constructors

When decoding Bech32/Bech32m into a secret wrapper, use the HRP-validating inherent methods on `Fixed` and `Dynamic` rather than the `_unchecked` variants:

```rust
#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::Fixed;

    // BIP-173 test vector — valid checksum, HRP = "abcdef", payload = 20 bytes
    let encoded_str = "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";

    // Preferred: validates HRP, returns Bech32Error::UnexpectedHrp on mismatch
    let key = Fixed::<[u8; 20]>::try_from_bech32(encoded_str, "abcdef")
        .expect("valid bech32 with correct HRP");

    // Avoid in security-critical code: accepts any HRP silently
    // let key = Fixed::<[u8; 20]>::try_from_bech32_unchecked(encoded_str).expect("valid bech32");
    let _ = key;
}
```

Validated `try_from_bech32` / `try_from_bech32m` on `Fixed` and `Dynamic` compare HRP case-insensitively and prevent cross-protocol confusion attacks.

### Available traits

| Format            | Encode        | Decode                                                  | Infallible?           | Feature            |
| ----------------- | ------------- | ------------------------------------------------------- | --------------------- | ------------------ |
| Hex               | `ToHex`       | `FromHexStr`                                            | Encode yes, decode no | `encoding-hex`     |
| Base64URL         | `ToBase64Url` | `FromBase64UrlStr`                                      | Encode yes, decode no | `encoding-base64`  |
| Bech32 (BIP-173)  | `ToBech32`    | `FromBech32Str` / `Fixed::try_from_bech32`   | No                    | `encoding-bech32`  |
| Bech32m (BIP-350) | `ToBech32m`   | `FromBech32mStr` / `Fixed::try_from_bech32m` | No                    | `encoding-bech32m` |

**Decode-side note**: Decoded bytes are plaintext from the moment of decoding until they are wrapped. Wrap the result immediately — avoid binding the intermediate `Vec<u8>` to a long-lived variable.

**Auditing encoding exposure**: Direct wrapper calls (`to_hex`, `to_base64url`, `try_to_bech32`, `try_to_bech32m`) do not appear in a standard `expose_secret` / `with_secret` grep. Use this single command to surface all encoding exposure points regardless of pattern:

```sh
grep -rn 'expose_secret\|with_secret\|\.to_hex\|\.to_base64url\|try_to_bech32\|try_to_bech32m'
```

See [`ToHex`], [`ToBech32`], [`FromHexStr`], and sibling traits in the [API docs](https://docs.rs/secure-gate) for full method listings and error types.

## Equality

Enable the **`ct-eq`** feature and use **`.ct_eq()`** for all secret comparisons. It is deterministic, constant-time (via `subtle`), and exact — suitable for keys, nonces, MACs, tags, signatures, and variable-length secrets.

**Never use plain `==`** on secrets (`==` is not implemented on the wrappers).

```rust
#[cfg(feature = "ct-eq")]
{
    use secure_gate::{Dynamic, Fixed, ConstantTimeEq};

    let key_a = Fixed::new([0xAAu8; 32]);
    let key_b = Fixed::new([0xAAu8; 32]);
    assert!(key_a.ct_eq(&key_b));

    let blob_a: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    let blob_b: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    assert!(blob_a.ct_eq(&blob_b));
}
```

## Serde

`serde-deserialize` decodes directly to the inner type. After deserialization completes, temporary buffers for `Dynamic<Vec<u8>>` and `Dynamic<String>` are `Zeroizing`-wrapped — oversized buffers are zeroized even on rejection. The default limit is `MAX_DESERIALIZE_BYTES` (1 MiB); call `Dynamic::deserialize_with_limit` to set a custom ceiling. Serialization requires the `SerializableSecret` marker trait.

> **Note:** `MAX_DESERIALIZE_BYTES` (and `deserialize_with_limit`) is enforced *after* the upstream deserializer has fully materialized the payload. It is a result-length acceptance bound, not a pre-allocation DoS guard. For untrusted input, enforce size limits at the transport or parser layer upstream.

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

Read [SECURITY.md](SECURITY.md) for the full threat model and mitigations.

## License

MIT OR Apache-2.0
