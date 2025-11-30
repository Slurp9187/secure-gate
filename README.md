# secure-gate

Zero-cost, `no_std`-compatible wrappers for handling sensitive data in memory.

- `Fixed<T>` – stack-allocated, zero-cost wrapper.
- `Dynamic<T>` – heap-allocated wrapper with full `.into()` ergonomics.
- When the `zeroize` feature is enabled, `FixedZeroizing<T>` and `DynamicZeroizing<T>` provide automatic zeroing on drop.

**Now with `conversions` — the most requested ergonomics upgrade ever.**

## Installation

```toml
[dependencies]
secure-gate = "0.5.8"
```

Recommended (full power):

```toml
secure-gate = { version = "0.5.8", features = ["zeroize", "rand", "conversions"] }
```

## Features

| Feature       | Description                                                                                     |
|---------------|-------------------------------------------------------------------------------------------------|
| `zeroize`     | Automatic memory wiping on drop (via `zeroize` + `secrecy`) — **recommended**                   |
| `rand`        | `SecureRandomExt::random()` — cryptographically secure key generation                         |
| `conversions` | **NEW** — `.to_hex()`, `.to_hex_upper()`, `.to_base64url()`, and `.ct_eq()` on all fixed secrets |
| `serde`       | Optional serialization (deserialization disabled on `Dynamic<T>` for security)                 |

Works in `no_std` + `alloc`. Only pay for what you use.

## Quick Start

```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(Aes256Key, 32);
fixed_alias!(FileKey, 32);
dynamic_alias!(Password, String);

// Cryptographically secure random keys
#[cfg(feature = "rand")]
{
    use secure_gate::SecureRandomExt;
    let key = Aes256Key::random();           // <80ns, thread-local OsRng
    let file_key = FileKey::random();
}

// Full ergonomics — with `conversions` feature
#[cfg(feature = "conversions")]
{
    use secure_gate::SecureConversionsExt;
    let hex = file_key.to_hex();             // "a1b2c3d4..."
    let b64 = file_key.to_base64url();       // safe for JSON, URLs
    assert!(file_key.ct_eq(&file_key));      // constant-time, timing-attack proof
}

// Heap secrets — pure joy
let pw: Password = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");
```

## Secure Conversions — `conversions` feature

```rust
#[cfg(feature = "conversions")]
{
    use secure_gate::{fixed_alias, SecureConversionsExt, SecureRandomExt};

    fixed_alias!(FileKey, 32);
    let key = FileKey::random();

    println!("Key (hex):       {}", key.to_hex());
    println!("Key (Base64URL): {}", key.to_base64url());
    assert!(key.ct_eq(&key));  // required for secure comparison
}
```

- `.to_hex()` / `.to_hex_upper()` → perfect for logging, debugging
- `.to_base64url()` → ideal for JSON export, URLs, config files
- `.ct_eq()` → **mandatory** for secure equality — prevents timing attacks

## Memory Guarantees (`zeroize` enabled)

| Type                     | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes                         |
|--------------------------|------------|-----------|-----------|------------------|-------------------------------|
| `Fixed<T>`               | Stack      | Yes       | Yes       | Yes (no heap)    | Zero-cost                     |
| `Dynamic<T>`             | Heap       | Yes       | Yes       | No (until drop)  | Use `finish_mut()` to shrink  |
| `FixedZeroizing<T>`      | Stack      | Yes       | Yes       | Yes              | RAII wrapper                  |
| `DynamicZeroizing<T>`    | Heap       | Yes       | Yes       | No (until drop)  | `SecretBox` prevents copies   |

**Important**: `DynamicZeroizing<T>` uses `.expose_secret()` — no `Deref`.

## Macros

```rust
// Fixed-size secrets
secure!([u8; 32], rng.gen())                    // → Fixed<[u8; 32]>

// Heap secrets
secure!(String, "pw".into())                    // → Dynamic<String>
secure!(heap Vec<u8>, payload)                  // → Dynamic<Vec<u8>>

// Type aliases — the recommended way
fixed_alias!(Aes256Key, 32)
dynamic_alias!(Password, String)
```

## Example Aliases

```rust
fixed_alias!(Aes256Key, 32);
fixed_alias!(XChaCha20Nonce, 24);
dynamic_alias!(Password, String);
dynamic_alias!(JwtSigningKey, Vec<u8>);

#[cfg(all(feature = "rand", feature = "conversions"))]
{
    use secure_gate::{SecureRandomExt, SecureConversionsExt};
    let key = Aes256Key::random();
    let hex = key.to_hex();          // only with `conversions`
    let pw: Password = "hunter2".into();
}
```

### Zero-cost — proven on real hardware

| Implementation             | Median time | Overhead vs raw |
|----------------------------|-------------|-----------------|
| raw `[u8; 32]`             | ~460 ps     | —               |
| `Fixed<[u8; 32]>`          | ~460 ps     | **+28 ps         |
| `fixed_alias!(Key, 32)`    | ~475 ps     | **+13 ps**      |

Overhead is **< 0.1 CPU cycles** — indistinguishable from raw arrays.

[View full report](https://slurp9187.github.io/secure-gate/benches/fixed_vs_raw/report/)

## Migration from v0.4.x

- `SecureGate<T>` → `Fixed<T>` (stack) or `Dynamic<T>` (heap)
- `.expose_secret()` → `value.expose_secret()`
- Automatic zeroing → `FixedZeroizing<T>` or `DynamicZeroizing<T>`

**Note**: `.view()` and `.view_mut()` deprecated in v0.5.5 → removed in v0.6.0.

## Changelog

[CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License

MIT OR Apache-2.0