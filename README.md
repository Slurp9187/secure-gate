# secure-gate

Zero-cost, `no_std`-compatible secure wrappers for secrets — stack for fixed-size, heap for dynamic.

## Features

| Feature  | Effect |
|----------|--------|
| `zeroize` | Enables wiping + auto-drop zeroing (on by default) |
| `serde`  | Serialization support |

- `no_std` + `alloc` compatible.
- Redacted `Debug`.
- Test coverage includes zero-cost, wiping, ergonomics, serde, macros.

**Memory Safety Guarantees (when `zeroize` enabled)**:
- Fixed-size secrets (`Fixed<T>`) use `zeroize::Zeroizing<T>` — stack-allocated, auto-zeroed.
- Dynamic secrets (`Dynamic<T>`) use `secrecy::SecretBox<T>` — heap-allocated, leak-resistant.
- On drop or `zeroize()`, `Vec<u8>` and `String` secrets are **completely deallocated** (not just zeroed).
  - Verified via unsafe inspection: capacity drops to 0, buffer is freed.
  - Stronger than full-capacity wiping — no slack memory remains.

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
use secure_gate::{Fixed, Dynamic, secure, fixed_alias};

// Fixed-size key (stack when zeroize off)
fixed_alias!(Aes256Key, 32);
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

Use `fixed_alias!` for fixed-size types and `dynamic_alias!` for dynamic types. These generate self-documenting aliases.

### Fixed-Size (Stack-Optimized)

```rust
use secure_gate::fixed_alias;

// Crypto keys
fixed_alias!(Aes256Key, 32);
fixed_alias!(HmacSha256Key, 32);
fixed_alias!(X25519SecretKey, 32);

// Nonces and IVs
fixed_alias!(AesGcmIv12, 12);
fixed_alias!(AesCbcIv16, 16);
fixed_alias!(ChaCha20Nonce12, 12);
fixed_alias!(XChaCha20Nonce24, 24);

// Salts
fixed_alias!(Salt16, 16);

// Usage
let key: Aes256Key = [0u8; 32].into();
let iv = AesGcmIv12::new(rand::random::<[u8; 12]>());
```

### Dynamic-Size (Heap-Optimized)

```rust
use secure_gate::dynamic_alias;

// Strings and passwords
dynamic_alias!(Password, String);
dynamic_alias!(JwtSecret, String);

// Byte vectors
dynamic_alias!(Token, Vec<u8>);
dynamic_alias!(Payload, Vec<u8>);

// Usage
let pw: Password = Dynamic::new("hunter2".to_string());
let token: Token = Dynamic::new_boxed(Box::new(vec![0u8; 32]));

assert_eq!(pw.len(), 7);
pw.push('!');  // DerefMut
assert_eq!(&*pw, "hunter2!");
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