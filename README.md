# secure-gate

Zero-cost, `no_std`-compatible wrappers for handling sensitive data in memory.

- `Fixed<T>` – stack-allocated, zero-cost wrapper.
- `Dynamic<T>` – heap-allocated wrapper with full `.into()` ergonomics.
- When the `zeroize` feature is enabled, `FixedZeroizing<T>` and `DynamicZeroizing<T>` provide automatic zeroing on drop.

**Now with `conversions` — safe, explicit, and still the most ergonomic secret conversions in Rust.**

## Installation

```toml
[dependencies]
secure-gate = "0.5.10"
```

Recommended (maximum safety + ergonomics):

```toml
secure-gate = { version = "0.5.10", features = ["zeroize", "rand", "conversions"] }
```

## Features

| Feature       | Description                                                                                              |
|---------------|----------------------------------------------------------------------------------------------------------|
| `zeroize`     | Automatic memory wiping on drop — **strongly recommended**                                               |
| `rand`        | `SecureRandomExt::random()` — cryptographically secure key generation                                   |
| `conversions` | **Safe** `.to_hex()`, `.to_base64url()`, `.ct_eq()` — **requires explicit `.expose_secret()`** since v0.5.9 |
| `serde`       | Optional serialization (deserialization intentionally disabled on `Dynamic<T>` for security)             |

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

// Secure conversions — explicit exposure required (v0.5.9+)
#[cfg(feature = "conversions")]
{
    let hex  = file_key.expose_secret().to_hex();        // loud, safe, intentional
    let b64  = file_key.expose_secret().to_base64url();  // perfect for JSON/URLs
    let same = file_key.expose_secret().ct_eq(other.expose_secret());

    println!("Key (hex):       {hex}");
    println!("Key (Base64URL): {b64}");
}

// Heap secrets — still pure joy
let pw: Password = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");
```

## Secure Conversions — `conversions` feature (v0.5.9+)

```rust
#[cfg(all(feature = "rand", feature = "conversions"))]
{
    use secure_gate::{fixed_alias, SecureRandomExt};

    fixed_alias!(JwtKey, 32);
    let key = JwtKey::random();

    // Explicit exposure — this is intentional and visible in code reviews
    let token_material = key.expose_secret().to_base64url();
    let debug_hex      = key.expose_secret().to_hex_upper();

    assert!(key.expose_secret().ct_eq(key.expose_secret())); // constant-time safe
}
```

**Why `.expose_secret()` is required**  
Starting with v0.5.9, all conversion methods live on the exposed `&[u8]` slice. This guarantees:
- Every secret exposure is **grep-able** and **review-visible**
- no accidental silent leaks
- full compatibility with the `secrecy` / `zeroize` ecosystem philosophy

Old direct methods (e.g. `key.to_hex()`) are **deprecated** and will be removed in v0.6.0.

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
    use secure_gate::{SecureRandomExt};
    let key = Aes256Key::random();
    let hex = key.expose_secret().to_hex();          // explicit, safe, loud
    let pw: Password = "hunter2".into();
}
```

### Zero-cost — proven on real hardware

| Implementation             | Median time | Overhead vs raw |
|----------------------------|-------------|-----------------|
| raw `[u8; 32]`             | ~460 ps     | —               |
| `Fixed<[u8; 32]>`         | ~460 ps     | **+28 ps**      |
| `fixed_alias!(Key, 32)`    | ~475 ps     | **+13 ps**      |

Overhead is **< 0.1 CPU cycles** — indistinguishable from raw arrays.

[View full report](https://slurp9187.github.io/secure-gate/benches/fixed_vs_raw/report/)

## Migration from v0.5.8

If you were using the `conversions` feature:

```diff
- let hex = key.to_hex();
+ let hex = key.expose_secret().to_hex();
```

The old methods are deprecated and will be removed in v0.6.0.

## Changelog

[CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License

MIT OR Apache-2.0