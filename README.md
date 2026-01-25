# secure-gate
`no_std`-compatible wrappers for sensitive data with explicit, auditable exposure.

> 🔒 **Security Notice**: This crate has **not undergone independent audit**.
> Review the code and [SECURITY.md](SECURITY.md) before production use.
> Memory safety is guaranteed — **no unsafe code** (`#![forbid(unsafe_code)]`).

Secure-gate provides `Dynamic<T>` (heap-allocated) and `Fixed<T>` (stack-allocated) wrappers that **force explicit access** to secrets via `.expose_secret()` or scoped `.with_secret()` — preventing accidental leaks while remaining zero-cost and `no_std` + `alloc` compatible.

## Why secure-gate?

- **Orthogonal encoding/decoding** — per-format traits (e.g., `ToHex`/`FromHexStr`) with symmetric APIs and umbrella traits for aggregation
- **Extensible** — adding new formats (e.g., base58) requires only one new trait pair + impls

- **Explicit exposure** — no silent `Deref`/`AsRef` leaks
- **Zeroize on drop** (`zeroize` feature)
- **Timing-safe equality** (`ct-eq` feature)
- **Fast probabilistic equality for large secrets** (`hash-eq` → BLAKE3 + fixed digest compare)
- **Secure random generation** (`rand` feature)
- **Encoding** (symmetric per-format traits: hex, base64url, bech32/BIP-173, bech32m/BIP-350) + **serde** auto-detection (hex/base64url/bech32/bech32m)
- **Macros** for ergonomic aliases (`dynamic_alias!`, `fixed_alias!`)
- **Auditable** — every exposure and encoding call is grep-able

## Installation

```toml
[dependencies]
secure-gate = "0.7.0-rc.11"  # or latest stable version
```

**Recommended secure defaults**:
```toml
secure-gate = { version = "0.7.0-rc.11", features = ["secure"] }  # zeroize + ct-eq
```

**Batteries-included** (most features):
```toml
secure-gate = { version = "0.7.0-rc.11", features = ["full"] }
```

**Minimal** (no zeroize/ct-eq — discouraged for production):
```toml
secure-gate = { version = "0.7.0-rc.11", default-features = false }
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
| `serde-deserialize`    | Auto-detect hex/base64/bech32/bech32m when loading secrets                  | No       |
| `serde-serialize`      | Export secrets (gated by `SerializableType`)                                | No       |
| `encoding`             | Meta: symmetric per-format encoding/decoding (hex, base64url, bech32/bech32m) | No       |
| `encoding-hex`         | `ToHex` (`.to_hex()`, `.to_hex_upper()`) + `FromHexStr` (`.try_from_hex()`)  | No       |
| `encoding-base64`      | `ToBase64Url` (`.to_base64url()`) + `FromBase64UrlStr` (`.try_from_base64url()`) | No       |
| `encoding-bech32`      | Bech32/BIP-173 & Bech32m/BIP-350: `ToBech32`, `ToBech32m`, `FromBech32Str`, `FromBech32mStr` | No       |
| `cloneable`            | Opt-in cloning via `CloneableType` marker                                   | No       |
| `full`                 | All of the above (convenient for development)                               | No       |

`no_std` + `alloc` compatible. Disabled features have **zero overhead**.

## Quick Start

```rust
use secure_gate::{dynamic_alias, fixed_alias, ExposeSecret, ExposeSecretMut};

dynamic_alias!(pub Password, String);      // Dynamic<String>
fixed_alias!(pub Aes256Key, 32);           // Fixed<[u8; 32]>

let mut pw: Password = "hunter2".into();
let key: Aes256Key = [42u8; 32].into();

// Scoped (recommended)
pw.with_secret(|s| println!("length: {}", s.len()));

// Direct (auditable)
assert_eq!(pw.expose_secret(), "hunter2");

// Mutable
pw.with_secret_mut(|s| s.push('!'));
pw.expose_secret_mut().clear();

// Symmetric encoding/decoding example (new per-format traits)
#[cfg(all(feature = "encoding-hex", feature = "encoding-bech32"))]
{
    use secure_gate::{FromHexStr, ToBech32, ToHex};
    let hex    = key.expose_secret().to_hex();          // "2a2a2a..."
    let bech32 = key.expose_secret().to_bech32("key");  // "key1q..." (BIP-173)
    let roundtrip = hex.try_from_hex().unwrap();        // Decode back
}
```

> **Note**: Encoding API updated in 0.7.0 — old `SecureEncoding` removed in favor of per-format traits (e.g., `ToHex`, `FromHexStr`). Existing code like `data.to_hex()` still works via blanket impls. For new symmetric encoding/decoding, use individual traits or umbrellas (`SecureEncoding`/`SecureDecoding`).

## Recommended Equality

Use **`hash_eq_opt`** — it automatically chooses the best method:

- Small inputs (≤32 bytes default): fast deterministic `ct_eq`
- Large/variable inputs: fast BLAKE3 hashing + digest compare

```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::{Dynamic, HashEq};
    extern crate alloc;

    let sig_a: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();  // e.g. ML-DSA signature
    let sig_b: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();

    // Recommended: smart path selection
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
    use secure_gate::{Dynamic, Fixed};
    extern crate alloc;

    let token: Dynamic<Vec<u8>> = Dynamic::from_random(64);
    let key: Fixed<[u8; 32]> = Fixed::from_random();
}
```

### Encoding (symmetric per-format traits)

secure-gate provides **orthogonal, symmetric encoding/decoding traits** for extensibility:

- `ToHex` / `FromHexStr`: Hex encoding/decoding
- `ToBase64Url` / `FromBase64UrlStr`: Base64url encoding/decoding
- `ToBech32` / `FromBech32Str`: BIP-173 Bech32 encoding/decoding
- `ToBech32m` / `FromBech32mStr`: BIP-350 Bech32m encoding/decoding

Umbrellas (`SecureEncoding` / `SecureDecoding`) aggregate all enabled traits for convenience. Each format is independent—adding base58 later requires only one new pair.

All methods are blanket-implemented over `AsRef<[u8]>` (encoding) or `AsRef<str>` (decoding) for zero-overhead ergonomics.

```rust
#[cfg(all(feature = "rand", feature = "encoding-bech32", feature = "encoding-hex"))]
{
    use secure_gate::{fixed_alias, Fixed, ExposeSecret, ToBech32, ToHex, FromHexStr};
    extern crate alloc;

    fixed_alias!(Aes256Key, 32);
    let key: Aes256Key = Aes256Key::from_random();

    let hex    = key.expose_secret().to_hex();          // "2a2a2a..."
    let bech32 = key.expose_secret().to_bech32("key");  // "key1q..." (BIP-173)
    let bech32m = key.expose_secret().to_bech32m("key"); // "key1p..." (BIP-350)

    // Symmetric decoding
    let decoded_hex: Vec<u8> = "2a2a2a".try_from_hex().unwrap();
    let decoded_bech32 = "key1q...".try_from_bech32_expect_hrp("key").unwrap();
}
```

### Serde (auto-detects hex/base64url/bech32/bech32m on deserialize)

```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32", feature = "rand"))]
{
    use secure_gate::{fixed_alias, ExposeSecret, ToBech32};
    use serde_json;
    extern crate alloc;

    fixed_alias!(Aes256Key, 32);
    // Generate a key and encode to bech32
    let original: Aes256Key = Aes256Key::from_random();
    let bech32 = original.with_secret(|s| s.to_bech32("key"));
    let decoded: Aes256Key = serde_json::from_str(&format!("\"{}\"", bech32)).unwrap();
    // Auto-detection handles decoding transparently
}
```

## License

MIT OR Apache-2.0
