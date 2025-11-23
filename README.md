# secure-gate

Zero-cost, `no_std`-compatible wrappers for handling sensitive data in memory.

- `Fixed<T>` – stack-allocated, zero-cost wrapper.
- `Dynamic<T>` – heap-allocated wrapper that forwards to the inner type.
- When the `zeroize` feature is enabled, `FixedZeroizing<T>` and `DynamicZeroizing<T>` provide automatic zeroing on drop.

## Installation

```toml
[dependencies]
secure-gate = "0.5.2"
```

With automatic zeroing (recommended for most use cases):

```toml
secure-gate = { version = "0.5.2", features = ["zeroize"] }
```

## Features

| Feature   | Description                                            |
|-----------|--------------------------------------------------------|
| `zeroize` | Enables `zeroize` integration (`Zeroizing`, `SecretBox`) |
| `serde`   | Optional serialization support                         |
| `alloc`   | Required for `Dynamic<T>` (enabled by default)         |
| `std`     | Not required – works in `no_std` environments          |

## Quick Start

```rust
use secure_gate::{secure, fixed_alias, dynamic_alias};

// Type aliases
fixed_alias!(Aes256Key, 32);
fixed_alias!(Nonce12, 12);
dynamic_alias!(Password, String);

// Construction
let key = Aes256Key::from(rng.gen());           // clean and explicit
let key2: Aes256Key = rng.gen().into();         // natural .into()
let key3 = Aes256Key::new(rng.gen());           // classic style

let nonce = Nonce12::from(rng.gen());
let nonce2: Nonce12 = rng.gen().into();

let mut password: Password = secure!(String, "hunter2".to_string());
password.push('!');
password.finish_mut(); // shrink_to_fit() on String/Vec<u8>

// Auto-zeroing variants (requires `zeroize` feature)
let temp_key = secure_gate::secure_zeroizing!([u8; 32], derive_key());
let secret_vec = secure_gate::secure_zeroizing!(heap Vec<u8>, Box::new(secret_bytes));
```

## Memory Guarantees (`zeroize` feature enabled)

| Type                     | Allocation | Auto-zero on drop | Full capacity wiped | Slack memory eliminated | Notes |
|--------------------------|------------|-------------------|---------------------|--------------------------|-------|
| `Fixed<T>`               | Stack      | Yes (via `Zeroizing`) | Yes             | Yes (no heap)            | No allocation |
| `Dynamic<T>`             | Heap       | Yes (via `SecretBox`) | Yes             | No (until drop)          | Use `finish_mut()` to shrink |
| `FixedZeroizing<T>`      | Stack      | Yes                | Yes             | Yes                      | RAII wrapper |
| `DynamicZeroizing<T>`    | Heap       | Yes                | Yes             | No (until drop)          | `SecretBox` prevents copies |

- All zeroing uses `zeroize::Zeroize` (volatile writes + compiler fence).
- `Vec<u8>` and `String` have their full current capacity zeroed and are truncated to length zero.
- The underlying allocation is freed on drop (standard Rust behavior); capacity is not forcibly reduced unless `finish_mut()` / `shrink_to_fit()` is called.
- Past reallocations may leave copies of data elsewhere in memory. Pre-allocate with the final expected size to avoid reallocations.

**Important**: `DynamicZeroizing<T>` (i.e. `SecretBox<T>`) is accessed via `.expose_secret()` and `.expose_secret_mut()` — it does **not** implement `Deref`.

## Macros

```rust
secure!([u8; 32], rng.gen())                    // Fixed<[u8; 32]>
secure!(String, "pw".into())                    // Dynamic<String>
secure!(Vec<u8>, data.to_vec())                 // Dynamic<Vec<u8>>

secure_zeroizing!([u8; 32], key)                // FixedZeroizing<[u8; 32]> (zeroize feature)
secure_zeroizing!(heap Vec<u8>, Box::new(data)) // DynamicZeroizing<Vec<u8>>

fixed_alias!(MyKey, 32)
dynamic_alias!(MySecret, Vec<u8>)
```

## Example Aliases

```rust
fixed_alias!(Aes128Key, 16);
fixed_alias!(Aes256Key, 32);
fixed_alias!(XChaCha20Nonce, 24);
dynamic_alias!(Password, String);
dynamic_alias!(JwtSigningKey, Vec<u8>);

// Usage
let key = Aes256Key::from(rng.gen());
let key2: Aes256Key = rng.gen().into();
```

## Migration from v0.4.x

- `SecureGate<T>` → `Fixed<T>` (stack) or `Dynamic<T>` (heap)
- `.expose_secret()` → direct deref (`&*value` or `&mut *value`) for `Fixed`/`Dynamic`
- Automatic zeroing → `FixedZeroizing<T>` or `DynamicZeroizing<T>` (with `zeroize` feature)

## Changelog

See [CHANGELOG.md](CHANGELOG.md)

## License

MIT OR Apache-2.0