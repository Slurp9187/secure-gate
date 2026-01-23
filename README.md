# secure-gate

`no_std`-compatible wrappers for sensitive data with explicit, auditable exposure.

> 🔒 **Security Notice**: This crate ***has not undergone independent audit***. Review the code and [SECURITY.md](SECURITY.md) before production use. Memory safety is guaranteed—no unsafe code (`#![forbid(unsafe_code)]`).

- `Fixed<T>` – Stack-allocated fixed-size secrets (e.g., keys, hashes).
- `Dynamic<T>` – Heap-allocated variable-size secrets (e.g., passwords, tokens).

Zeroizes memory on drop (when `zeroize` enabled). All access requires explicit `.expose_secret()` or scoped `.with_secret()` – no implicit leaks.

## Installation

```toml
[dependencies]
secure-gate = "0.7.0-rc.10"
```

**Secure defaults** (recommended):
```toml
secure-gate = "0.7.0-rc.10"  # Enables "secure" meta-feature (zeroize + ct-eq)
```

**Batteries-included**:
```toml
secure-gate = { version = "0.7.0-rc.10", features = ["full"] }
```

**Minimal** (no zeroization/ct-eq – **discouraged for production**):
```toml
secure-gate = { version = "0.7.0-rc.10", default-features = false }
```

## Features

| Feature              | Description                                                                                          |
|----------------------|------------------------------------------------------------------------------------------------------|
| `secure` (default)   | Meta-feature: `zeroize` + `ct-eq` (secure wiping + timing-safe equality)                              |
| `zeroize`            | Zeroizes memory on drop; enables safe cloning via `CloneableType`                                    |
| `ct-eq`              | `ConstantTimeEq` trait for timing-attack-resistant comparisons                                       |
| `hash-eq`            | `HashEq` trait: BLAKE3 hashing for large secrets (probabilistic safety)                               |
| `rand`               | Random generation (`from_random()`) via `OsRng`                                                       |
| `serde`              | Meta-feature: `serde-deserialize` + `serde-serialize`                                                 |
| `serde-deserialize`  | Load secrets via serde (auto-detects hex/base64/bech32)                                               |
| `serde-serialize`    | Export secrets via serde (gated by `SerializableType` marker)                                         |
| `encoding`           | Meta-feature: `encoding-hex` + `encoding-base64` + `encoding-bech32`                                  |
| `encoding-hex`       | Hex encoding/decoding (`to_hex()`, `to_hex_upper()`)                                                  |
| `encoding-base64`    | Base64 URL-safe encoding (`to_base64url()`)                                                           |
| `encoding-bech32`    | Bech32/Bech32m with HRP validation (`to_bech32()`, `try_to_bech32()`)                                  |
| `cloneable`          | `CloneableType` marker for opt-in cloning                                                              |
| `full`               | Meta-feature: `secure` + `encoding` + `hash-eq` + `cloneable`                                          |

`no_std` + `alloc` compatible. Features are zero-overhead when disabled.

## Security Model

Prioritizes **explicitness** and **auditability**:
- **No implicit access**: Requires `.expose_secret()`, `.expose_secret_mut()`, or scoped `.with_secret()`/`.with_secret_mut()`.
- **Dual exposure**: Scoped closures prevent long-lived leaks; direct refs are grep-able escape hatches.
- **Opt-in risks**: Cloning/serialization via markers (`CloneableType`, `SerializableType`).
- **Zero overhead**: Explicit calls are inlined/elided; no runtime cost for security.
- **No unsafe code**: Forbidden unconditionally.

See [SECURITY.md](SECURITY.md) for details.

## Quick Start

```rust
use secure_gate::{fixed_alias, dynamic_alias, ExposeSecret, ExposeSecretMut};

fixed_alias!(pub Aes256Key, 32);       // Fixed<[u8; 32]>
dynamic_alias!(pub Password, String);   // Dynamic<String>

let key: Aes256Key = [42u8; 32].into();
let mut pw: Password = "secret".into();

// Scoped access (preferred, prevents leaks)
let len = pw.with_secret(|s| s.len());

// Direct access (auditable)
assert_eq!(pw.expose_secret(), "secret");
let key_bytes = key.expose_secret();  // &[u8; 32]

// Mutable access
pw.with_secret_mut(|s| s.push('!'));
pw.expose_secret_mut().clear();
```

## Polymorphic Traits

Generic code across wrappers:

- **`ExposeSecret`/`ExposeSecretMut`**: Controlled access with length/is_empty metadata.
- **`ConstantTimeEq`**: Timing-safe byte equality.
- **`HashEq`**: Probabilistic BLAKE3-based equality for large data.
- **`SecureEncoding`**: String encoding/decoding.

```rust
use secure_gate::{Fixed, Dynamic, ExposeSecret, ConstantTimeEq};

fn check_len<T: ExposeSecret>(secret: &T) -> usize {
    secret.with_secret(|inner| inner.len())  // Generic over Fixed/Dynamic
}

#[cfg(feature = "ct-eq")]
fn secrets_equal<L, R>(left: &L, right: &R) -> bool
where
    L: ConstantTimeEq,
    R: ConstantTimeEq,
{
    left.ct_eq(right)  // Safe, constant-time
}
```

## Random Generation (`rand`)

Secure random bytes via system entropy.

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{Fixed, Dynamic};

    let key: Fixed<[u8; 32]> = Fixed::from_random();
    let data: Dynamic<Vec<u8>> = Dynamic::from_random(64);

    // Panics on RNG failure (fail-fast)
}
```

## Encoding (`encoding-*`)

Explicit string conversions via `SecureEncoding` trait.

**Outbound** (to strings):
```rust
#[cfg(feature = "encoding-hex")]
{
    let hex = [0u8; 16].to_hex();  // "0000000000000000"
}

#[cfg(feature = "encoding-base64")]
{
    let b64 = b"hello".to_base64url();  // "aGVsbG8"
}

#[cfg(feature = "encoding-bech32")]
{
    let bech32 = b"test".to_bech32("bc");  // "bc1qtest..."
}
```

**Inbound** (from strings via serde auto-detection):
```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
{
    let key: Dynamic<Vec<u8>> = serde_json::from_str(r#""deadbeef""#).unwrap();
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
{
    let data: Dynamic<Vec<u8>> = serde_json::from_str(r#""bc1qw508d..."#).unwrap();
}
```

Bech32 includes fallible `try_to_bech32()` for error handling.

## Equality

**Constant-Time (`ct-eq`)**: Direct byte comparison via `subtle`.
```rust
#[cfg(feature = "ct-eq")]
{
    let a: Fixed<[u8; 32]> = [0; 32].into();
    let b: Fixed<[u8; 32]> = [1; 32].into();
    assert!(!a.ct_eq(&b));  // Timing-safe
}
```

**Hash-Based (`hash-eq`)**: BLAKE3 + ct-eq on digest (better for large secrets).
```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::HashEq;
    assert!(a.hash_eq(&a));  // Probabilistic safety
}
```

`==` is not implemented—use these for security.

## Opt-In Cloning (`cloneable`)

Mark types for cloning with `CloneableType`.
```rust
#[cfg(feature = "cloneable")]
{
    use secure_gate::CloneableType;

    #[derive(Clone)]
    struct MyKey([u8; 32]);

    impl CloneableType for MyKey {}  // Opt-in

    let key = MyKey([0; 32]);
    let copy = key.clone();  // Now allowed
}
```

## Opt-In Serialization (`serde-serialize`)

Mark types for serde export with `SerializableType`.
```rust
#[cfg(feature = "serde-serialize")]
{
    use secure_gate::SerializableType;
    use serde::Serialize;

    #[derive(Serialize)]
    struct RawKey(Vec<u8>);

    impl SerializableType for RawKey {}  // Opt-in

    let key = RawKey(vec![1, 2, 3]);
    let json = serde_json::to_string(&key).unwrap();  // Allowed
}
```

## Construction

**Fixed** (exact sizes):
```rust
let fixed: Fixed<[u8; 4]> = [1, 2, 3, 4].into();  // Infallible
let tried: Result<Fixed<[u8; 4]>, _> = [1, 2, 3, 4].try_into();  // Fallible alternative
```

**Dynamic** (flexible):
```rust
let dyn_vec: Dynamic<Vec<u8>> = [1, 2, 3].as_slice().into();  // Infallible copy
let dyn_str: Dynamic<String> = "hello".into();  // Infallible
```

## Macros

Require explicit visibility (`pub`, `pub(crate)`, etc.).

### Basic Aliases
```rust
fixed_alias!(pub AesKey, 32);
dynamic_alias!(pub Password, String);
```

### With Custom Docs
```rust
fixed_alias!(pub ApiKey, 32, "Service API key");
dynamic_alias!(pub Token, Vec<u8>, "OAuth token");
```

### Generic Aliases
```rust
fixed_generic_alias!(pub Buffer);
dynamic_generic_alias!(pub Secret);
```

## Memory & Performance

**Zeroization** (`zeroize`):
- Stack: `Fixed<T>` wipes on drop.
- Heap: `Dynamic<T>` wipes full allocation, including slack (best-effort, not guaranteed in all environments).

**Performance**: Zero overhead—wrappers inline to raw types. Explicit exposure elided by optimizer.

## License

MIT OR Apache-2.0
