# secure-gate
`no_std`-compatible wrappers for sensitive data with explicit exposure requirements.

> 🔒 **Note**: This crate is in active development and ***has not undergone independent security audit***.  
> Please review it for your use case and handle sensitive data with care.

> See [SECURITY.md](SECURITY.md) for detailed security considerations.

- `Fixed<T>` — Stack-allocated wrapper  
- `Dynamic<T>` — Heap-allocated wrapper  

Memory containing secrets is zeroed on drop, including spare capacity where applicable (when `zeroize` is enabled).

Access requires an explicit `.expose_secret()` (or `.expose_secret_mut()`) call — no `Deref` or implicit paths.

## Installation

```toml
[dependencies]
secure-gate = "0.7.0-rc.10"
```

Basic configuration includes `zeroize` and `ct-eq` (via the `secure` meta-feature) for secure memory handling and constant-time equality.

**Recommended for most users** (secure defaults):
```toml
secure-gate = "0.7.0-rc.10" # default enables "secure"
```

**Batteries-included** (all optional features):
```toml
secure-gate = { version = "0.7.0-rc.10", features = ["full"] }
```

**Constrained/minimal builds** (no zeroization or ct-eq — **strongly discouraged** for production):
```toml
secure-gate = { version = "0.7.0-rc.10", default-features = false }
```

## Features

| Feature              | Description                                                                                          |
|----------------------|------------------------------------------------------------------------------------------------------|
| `secure` (default)   | Enables `zeroize` + `ct-eq` — secure memory wiping and constant-time equality (recommended)         |
| `zeroize`            | Memory zeroing on drop + opt-in safe cloning (requires `zeroize` crate)                              |
| `ct-eq`              | Constant-time equality checks to prevent timing attacks (requires `subtle` crate)                   |
| `hash-eq`            | Fast hash-based equality (BLAKE3 hashing with constant-time hash comparison, requires `blake3` and `ct-eq`) |
| `cloneable`          | Opt-in safe cloning wrappers and `CloneableType` marker                         |
| `encoding`           | All encoding support (`encoding-base64`, `encoding-bech32`, `encoding-hex`)                          |
| `encoding-base64`    | Base64 encoding/decoding + constructors (requires `base64` crate)                                    |
| `encoding-bech32`    | Bech32 encoding/decoding + constructors (requires `bech32` crate)                                    |
| `encoding-hex`       | Hex encoding/decoding + constructors (requires `hex` crate)                                          |
| `rand`               | Secure random generation (`from_random()`) (requires `rand` crate)                                   |
| `serde`              | Meta-feature enabling both `serde-deserialize` and `serde-serialize`                                 |
| `serde-deserialize`  | Serde `Deserialize` support for loading secrets (requires `serde` crate)                             |
| `serde-serialize`    | Serde `Serialize` support (gated by `SerializableType` marker) (requires `serde` crate)             |
| `full`               | Meta-feature enabling `secure`, `encoding`, `hash-eq`, and `cloneable` features                      |

`no_std` + `alloc` compatible. Features add no overhead when unused.

## Security Model & Design Philosophy

`secure-gate` prioritizes **auditability** and **explicitness** over implicit convenience.

All secret access requires an explicit `.expose_secret()` (or `.expose_secret_mut()`) call — making exposures grep-able and preventing hidden leaks.

These calls are zero-cost `#[inline(always)]` reborrows (fully elided by the optimizer). The explicitness is deliberate for humans and auditors, with **no runtime overhead**.

## Quick Start

```rust
use secure_gate::{fixed_alias, dynamic_alias, ExposeSecret, ExposeSecretMut};

// Recommended: semantic aliases for clarity
fixed_alias!(pub Aes256Key, 32);     // Fixed<[u8; 32]>
dynamic_alias!(pub Password, String); // Dynamic<String>

// Create secrets
let key: Aes256Key = [0u8; 32].into();           // From array/slice
let mut pw: Password = "hunter2".into();         // From &str or String

// Access (zero-cost)
assert_eq!(pw.expose_secret(), "hunter2");
let key_bytes = key.expose_secret(); // &[u8; 32]

// Mutable access
pw.expose_secret_mut().push('!');
```

## Polymorphic Traits for Generic Operations

The `secure-gate` crate provides polymorphic traits that enable writing generic code across different secret wrapper types while maintaining security guarantees:

- `ExposeSecret` & `ExposeSecretMut`: Polymorphic secret access with controlled mutability
- `ConstantTimeEq`: Constant-time equality (requires `ct-eq`)
- `HashEq`: Probabilistic constant-time equality via BLAKE3 hashing (requires `hash-eq`)
- `SecureEncoding`: Extension for string encoding (requires encoding features)

### Usage Example

```rust
use secure_gate::{Fixed, Dynamic, ExposeSecret};

let fixed_secret: Fixed<[u8; 32]> = [0u8; 32].into();
let fixed_len = fixed_secret.expose_secret().len();

let dynamic_secret: Dynamic<String> = "secret".into();
let dynamic_len = dynamic_secret.expose_secret().len();
```

## Random Generation (`rand` feature)

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{Fixed, Dynamic, ExposeSecret};

    let key: Fixed<[u8; 32]> = Fixed::from_random();
    let random_bytes: Dynamic<Vec<u8>> = Dynamic::from_random(64);

    assert_eq!(key.len(), 32);
    assert_eq!(random_bytes.len(), 64);
}
```

`from_random()` uses system entropy (`OsRng`) — guaranteed cryptographically secure randomness. Panics on RNG failure (fail-fast for crypto code).

## Encoding (`encoding-*` features)

Outbound encoding uses the `SecureEncoding` trait (returns `String`):

```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::{Fixed, SecureEncoding, ExposeSecret};

    let secret: Fixed<[u8; 16]> = [0u8; 16].into();

    let hex = secret.expose_secret().to_hex();         // String: "000000..."
    let hex_upper = secret.expose_secret().to_hex_upper(); // "000000..."
}

#[cfg(feature = "encoding-base64")]
{
    use secure_gate::SecureEncoding;

    let bytes = b"Hello".as_slice();
    let base64 = bytes.to_base64url(); // "SGVsbG8"
}

#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::SecureEncoding;

    let bytes = b"hello".as_slice();
    let bech32 = bytes.to_bech32("bc");   // panics on error
    let bech32m = bytes.to_bech32m("tb"); // panics on error
}
```

Inbound decoding via Serde deserialization (auto-detects encoding from strings):

```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
{
    use secure_gate::Dynamic;

    // Auto-detects hex from JSON string
    let key: Dynamic<Vec<u8>> = serde_json::from_str(r#""deadbeef""#).unwrap();
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
{
    use secure_gate::Dynamic;

    // Auto-detects base64 from JSON string
    let data: Dynamic<Vec<u8>> = serde_json::from_str(r#""SGVsbG8""#).unwrap(); // "Hello"
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
{
    use secure_gate::Dynamic;

    // Auto-detects bech32 from JSON string (requires valid HRP)
    let data: Dynamic<Vec<u8>> = serde_json::from_str(r#""bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4""#).unwrap();
}
```

## Constant-Time Equality (`ct-eq` feature)

```rust
#[cfg(feature = "ct-eq")]
{
    use secure_gate::Fixed;

    let a: Fixed<[u8; 32]> = [0u8; 32].into();
    let b: Fixed<[u8; 32]> = [1u8; 32].into();

    assert!(a.ct_eq(&a));
    assert!(!a.ct_eq(&b));
}
```

## Hash-Based Equality (`hash-eq` feature)

```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::{Fixed, HashEq};

    let a: Fixed<[u8; 32]> = [0u8; 32].into();
    let b: Fixed<[u8; 32]> = [1u8; 32].into();

    assert!(a.hash_eq(&a));
    assert!(!a.hash_eq(&b));
}
```

## Opt-In Safe Cloning (`cloneable` feature)

Cloning is opt-in via `CloneableType` marker and convenience macros.

```rust
#[cfg(feature = "cloneable")]
use secure_gate::{cloneable_fixed_alias, cloneable_dynamic_alias, ExposeSecret};

#[cfg(feature = "cloneable")]
{
    extern crate alloc;

    cloneable_fixed_alias!(pub CloneableKey, 32);
    cloneable_dynamic_alias!(pub CloneablePassword, String);

    let key: CloneableKey = [0u8; 32].into();
    let pw: CloneablePassword = "hunter2".to_string().into();

    let key2 = key.clone();   // Safe deep clone
    let pw2 = pw.clone();
}
```

Custom:
```rust
#[cfg(feature = "cloneable")]
use secure_gate::CloneableType;

#[cfg(feature = "cloneable")]
{
    use zeroize::Zeroize;

    #[derive(Clone, Zeroize)]
    struct MyKey([u8; 32]);

    impl CloneableType for MyKey {}

    let key = MyKey([42u8; 32]);
    let copy = key.clone();
}
```

## Opt-In Serialization (`serde-serialize` feature)

Raw serialization is opt-in via `SerializableType` marker and convenience macros (risky — audit carefully).

```rust
#[cfg(feature = "serde-serialize")]
use secure_gate::serializable_fixed_alias;

#[cfg(feature = "serde-serialize")]
{
    extern crate alloc;

    serializable_fixed_alias!(pub ExportableKey, 32);

    let key: ExportableKey = [0u8; 32].into();

    // Serialize to JSON
    let serialized = serde_json::to_string(&key).unwrap();
    println!("{}", serialized);
}
```

Custom:
```rust
#[cfg(feature = "serde-serialize")]
use secure_gate::SerializableType;

#[cfg(feature = "serde-serialize")]
{
    use serde::Serialize;

    #[derive(Serialize)]
    struct RawKey([u8; 32]);

    impl SerializableType for RawKey {}

    let key = RawKey([42u8; 32]);

    // Serialize to JSON (or other formats as needed)
    let serialized = serde_json::to_string(&key).unwrap();
    println!("{}", serialized);  // e.g., outputs the byte array as JSON
}
```

## Macros

All macros require explicit visibility.

### Basic Aliases

```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub Aes256Key, 32);     // Fixed<[u8; 32]>
dynamic_alias!(pub Password, String); // Dynamic<String>
```

With custom documentation:

```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub ApiKey, 32, "API key for service authentication");
dynamic_alias!(pub Token, Vec<u8>, "OAuth access token");
```

### Generic Aliases

```rust
use secure_gate::{fixed_generic_alias, dynamic_generic_alias};

fixed_generic_alias!(pub GenericFixedBuffer);
dynamic_generic_alias!(pub GenericHeapSecret, Vec<u8>);
```

## Memory Guarantees (`zeroize` enabled)

| Type          | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes                  |
|---------------|------------|-----------|-----------|------------------|------------------------|
| `Fixed<T>`    | Stack      | Yes       | Yes       | Yes (no heap)    | —                      |
| `Dynamic<T>`  | Heap       | Yes       | Yes       | Yes              | Full capacity wiped on drop |

## Performance

The wrappers add no runtime overhead compared to raw types in benchmarks.

## Security

For in-depth security analysis, see [SECURITY.md](SECURITY.md).

## License

MIT OR Apache-2.0