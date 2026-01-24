# secure-gate
`no_std`-compatible wrappers for sensitive data with explicit, auditable exposure.

> 🔒 **Security Notice**: This crate has **not undergone independent audit**.  
> Review the code and [SECURITY.md](SECURITY.md) before production use.  
> Memory safety is guaranteed — **no unsafe code** (`#![forbid(unsafe_code)]`).

Secure-gate provides `Dynamic<T>` (heap-allocated) and `Fixed<T>` (stack-allocated) wrappers that **force explicit access** to secrets via `.expose_secret()` or scoped `.with_secret()` — preventing accidental leaks while remaining zero-cost and `no_std` + `alloc` compatible.

## Why secure-gate?

- **Explicit exposure** — no silent `Deref`/`AsRef` leaks
- **Zeroize on drop** (`zeroize` feature)
- **Timing-safe equality** (`ct-eq` feature)
- **Fast probabilistic equality for large secrets** (`hash-eq` → BLAKE3 + fixed digest compare)
- **Secure random generation** (`rand` feature)
- **Encoding** (hex, base64url, bech32) + **serde** auto-detection (hex/base64/bech32)
- **Macros** for ergonomic aliases (`dynamic_alias!`, `fixed_alias!`)
- **Auditable** — every exposure is grep-able

## Installation

```toml
[dependencies]
secure-gate = "0.7.0-rc.10"  # or latest stable version
```

**Recommended secure defaults**:
```toml
secure-gate = { version = "0.7.0-rc.10", features = ["secure"] }  # zeroize + ct-eq
```

**Batteries-included** (most features):
```toml
secure-gate = { version = "0.7.0-rc.10", features = ["full"] }
```

**Minimal** (no zeroize/ct-eq — discouraged for production):
```toml
secure-gate = { version = "0.7.0-rc.10", default-features = false }
```

See [Features](#features) for the full list.

## Features

| Feature                | Description                                                                 | Default? |
|------------------------|-----------------------------------------------------------------------------|----------|
| `secure`               | Meta: `zeroize` + `ct-eq` (wiping + timing-safe equality)                   | Yes      |
| `zeroize`              | Zero memory on drop                                                         | No       |
| `ct-eq`                | `ConstantTimeEq` trait (prevents timing attacks)                            | No       |
| `hash-eq`              | `HashEq` trait: BLAKE3-based equality (fast for large/variable secrets)     | No       |
| `rand`                 | Secure random via `OsRng` (`from_random()`)                                 | No       |
| `serde`                | Meta: `serde-deserialize` + `serde-serialize`                               | No       |
| `serde-deserialize`    | Auto-detect hex/base64/bech32 when loading secrets                          | No       |
| `serde-serialize`      | Export secrets (gated by `SerializableType`)                                | No       |
| `encoding`             | Meta: hex + base64url + bech32                                              | No       |
| `encoding-hex`         | `.to_hex()` / `.to_hex_upper()`                                             | No       |
| `encoding-base64`      | `.to_base64url()`                                                           | No       |
| `encoding-bech32`      | `.to_bech32(hrp)` / `.try_to_bech32(hrp)`                                   | No       |
| `cloneable`            | Opt-in cloning via `CloneableType` marker                                   | No       |
| `full`                 | All of the above (convenient for development)                               | No       |

`no_std` + `alloc` compatible. Disabled features have **zero overhead**.

## Quick Start

```rust
use secure_gate::{dynamic_alias, fixed_alias, ExposeSecret, ExposeSecretMut};
extern crate alloc;

dynamic_alias!(pub Password, String); // Dynamic<String>
fixed_alias!(pub Aes256Key, 32);      // Fixed<[u8; 32]>

let mut pw: Password = "hunter2".into();
let key: Aes256Key = [42u8; 32].into();

// Scoped (preferred)
pw.with_secret(|s| println!("length: {}", s.len()));

// Direct (auditable)
assert_eq!(pw.expose_secret(), "hunter2");

// Mutable
pw.with_secret_mut(|s| s.push('!'));
pw.expose_secret_mut().clear();
```

## Recommended Equality

Use **`hash_eq_opt`** — it automatically chooses the best method:

- Small inputs (≤32 bytes default): fast deterministic `ct_eq`
- Large/variable inputs: fast BLAKE3 hashing + digest compare

```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::{Dynamic, HashEq};

    let sig_a: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();  // e.g. ML-DSA signature
    let sig_b: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();

    // Recommended: uses ct_eq for small, hash_eq for large
    if sig_a.hash_eq_opt(&sig_b, None) {
        // equal
    }

    // Force ct_eq even on large input
    sig_a.hash_eq_opt(&sig_b, Some(4096));
}
```

Plain `hash_eq` is still available for uniform probabilistic behavior.

See [docs](https://docs.rs/secure-gate) for full API.

## Security Model

- **Explicit access only** — `.expose_secret()` / `.with_secret()` required
- **No implicit leaks** — no `Deref`/`AsRef`/`Copy` by default
- **Zeroize** on drop (`zeroize` feature)
- **Timing-safe** equality (`ct-eq`)
- **Probabilistic fast equality** for big data (`hash-eq`)
- **No unsafe code** — enforced with `#![forbid(unsafe_code)]`

Read [SECURITY.md](SECURITY.md) for threat model and mitigations.

## Advanced Usage

### Macros for Aliases

```rust
use secure_gate::{dynamic_alias, fixed_alias};

dynamic_alias!(pub RefreshToken, String, "OAuth refresh token");
fixed_alias!(pub ApiKey, 32, "32-byte API key");
```

### Random Generation

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{fixed_alias, Dynamic};
    
    fixed_alias!(Aes256Key, 32);
    let key: Aes256Key = Aes256Key::from_random();
    let token: Dynamic<Vec<u8>> = Dynamic::from_random(64);
}
```

### Encoding

```rust
#[cfg(all(feature = "rand", feature = "encoding-hex"))]
{
    use secure_gate::{dynamic_alias, fixed_alias, ExposeSecret, SecureEncoding};
    extern crate alloc;

    fixed_alias!(Aes256Key, 32);
    let key: Aes256Key = Aes256Key::from_random();
    let hex = key.expose_secret().to_hex(); // "2a2a2a..."
}
```

### Serde (auto-detects hex/base64/bech32 on deserialize)

```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex", feature = "rand"))]
{
    use secure_gate::fixed_alias;
    
    fixed_alias!(Aes256Key, 32);
    let key: Aes256Key = serde_json::from_str(r#""000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f""#).unwrap();
}
```

## License

MIT OR Apache-2.0
