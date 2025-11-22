# secure-gate

**Experimental crate — under active development**

Zero-cost, `no_std`-compatible secure wrappers for secrets — stack for fixed-size, heap for dynamic.

**Current status**: The crate is in an experimental phase. The public API is stabilizing, but breaking changes are still expected in future minor releases. Use in production with caution. Community testing and critique encouraged — open issues for feedback on security, performance, or ergonomics. Fuzz targets pending validation; no stability claims until full testing.

## v0.5.0 – 2025-11-22

Major overhaul from v0.4.3's learning-phase API. Clean break for simplicity and correctness.

### Breaking Changes
- Replaced `SecureGate<T>` with two honest types: `Fixed<T>` (stack/fixed-size) and `Dynamic<T>` (heap/dynamic).
- Removed `ZeroizeMode` and manual wiping — `zeroize` ≥1.8 handles spare capacity by default.
- Removed password specializations (`SecurePassword`, `SecurePasswordBuilder`) — use `Dynamic<String>`.
- Removed `unsafe-wipe` — safe by default.
- Migration guide below.

### Added
- True zero-cost for fixed-size secrets when `zeroize` off (no heap allocation).
- `Deref` / `DerefMut` ergonomics — secrets borrow like normal types.
- `secure!` and `fixed_secret!` macros for constructors and aliases.
- `into_inner()` for extraction.
- `finish_mut()` with `shrink_to_fit` for `Dynamic<String>` / `Vec<u8>`.
- `Clone` for `Dynamic<T>`.

### Fixed
- No `unsafe` when `zeroize` off (`forbid(unsafe_code)`).
- Full spare-capacity wipe via `zeroize`.
- Consistent API across modes.

### Improved
- Modular structure (`fixed.rs`, `dynamic.rs`, `macros.rs`, `zeroize.rs`, `serde.rs`).
- 9 unit tests covering zero-cost, wiping, ergonomics, serde, macros.

Fuzz testing in progress — stability claims pending full validation.

## Features

| Feature  | Effect |
|----------|--------|
| `zeroize` | Enables wiping + auto-drop zeroing (on by default) |
| `serde`  | Serialization support |

- `no_std` + `alloc` compatible.
- Redacted `Debug`.
- Test coverage includes zero-cost, forwarding, and drop behavior.

**Internal Usage of Dependencies**:
- `Fixed<T>` uses `zeroize::Zeroizing<T>` for stack-allocated, auto-zeroing fixed-size secrets.
- `Dynamic<T>` uses `secrecy::SecretBox<T>` for heap-allocated, leak-protected dynamic secrets.
- Both forward `ZeroizeOnDrop` and `Zeroize` for seamless integration.

## Installation

```toml
[dependencies]
secure-gate = "0.5.0"
```

With serde:
```toml
secure-gate = { version = "0.5.0", features = ["serde"] }
```

## Quick Start

```rust
use secure_gate::{Fixed, Dynamic, secure, fixed_secret};

// Fixed-size key (stack when zeroize off)
fixed_secret!(Aes256Key, 32);
let key: Aes256Key = [0u8; 32].into();

assert_eq!(key.len(), 32);
key[0] = 1;  // DerefMut

// Dynamic password (heap, full protection)
let mut pw = Dynamic::<String>::new("hunter2".to_string());

assert_eq!(pw.len(), 7);
assert_eq!(&*pw, "hunter2");  // Deref

pw.push('!');
pw.finish_mut();  // shrink_to_fit

// Macros
let iv = secure!([u8; 16], [1u8; 16]);
assert_eq!(iv.0, [1u8; 16]);

// Extraction
let extracted = key.into_inner();
assert_eq!(extracted, [1u8; 32]);
```

## Example Aliases

Use `fixed_secret!` for domain-specific types:

```rust
use secure_gate::fixed_secret;

// Crypto keys
fixed_secret!(Aes256Key, 32);
fixed_secret!(HmacSha256Key, 32);
fixed_secret!(X25519SecretKey, 32);

// Nonces and IVs
fixed_secret!(AesGcmIv12, 12);
fixed_secret!(AesCbcIv16, 16);
fixed_secret!(ChaCha20Nonce12, 12);
fixed_secret!(XChaCha20Nonce24, 24);

// Salts
fixed_secret!(Salt16, 16);

// Usage
let key: Aes256Key = [0u8; 32].into();
let iv = AesGcmIv12::new(rand::random::<[u8; 12]>());
```

## Migration from v0.4.3

v0.5.0 is a clean break from v0.4.3's experimental API.

- `SecureGate<T>` → `Fixed<T>` (fixed-size) or `Dynamic<T>` (dynamic).
- `ZeroizeMode` / `new_full_wipe` → Removed; `zeroize` handles wiping.
- `SecurePassword` → `Dynamic<String>`.
- `expose_secret()` → `Deref` (e.g., `&*secret`).
- `unsafe-wipe` → Removed; safe by default.

Example migration:
```rust
// v0.4.3
let pw: SecurePassword = "hunter2".into();
pw.expose_secret_mut().push('!');

// v0.5.0
let mut pw = Dynamic::<String>::new("hunter2".to_string());
pw.push('!');
```

All v0.4.3 code breaks — this is intentional for the clean redesign.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full history.

## License

Dual-licensed under MIT OR Apache-2.0, at your option.