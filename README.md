# secure-gate
`no_std`-compatible wrappers for sensitive data with explicit exposure requirements.

<<<<<<< Updated upstream
> 🔒 **Note**: This crate is in active development and ***has not undergone independent security audit***. Please review it for your use case and handle sensitive data with care.

> See [SECURITY.md](SECURITY.md) for detailed security considerations.

- `Fixed<T>` — Stack-allocated wrapper
- `Dynamic<T>` — Heap-allocated wrapper
<<<<<<< Updated upstream

=======
- `FixedRandom<N>` — Stack-allocated cryptographically secure random bytes
- `DynamicRandom` — Heap-allocated cryptographically secure random bytes
- `CloneableArray<const N: usize>` — Cloneable fixed-size stack secret (`[u8; N]`)
- `CloneableString` — Cloneable heap-allocated text secret (`String`)
- `CloneableVec` — Cloneable heap-allocated binary secret (`Vec<u8>`)
- `HexString` — Validated lowercase hexadecimal string wrapper
- `Base64String` — Validated URL-safe base64 string wrapper (no padding)
- `Bech32String` — Validated Bech32/Bech32m string wrapper
 
=======
> 🔒 **Note**: This crate is in active development and ***has not undergone independent security audit***.  
> Please review it for your use case and handle sensitive data with care.

> See [SECURITY.md](SECURITY.md) for detailed security considerations.

- `Fixed<T>` — Stack-allocated wrapper  
- `Dynamic<T>` — Heap-allocated wrapper  

>>>>>>> Stashed changes
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
=======

<<<<<<< Updated upstream
>>>>>>> Stashed changes
| Feature | Description |
|---------------|------------------------------------------------------------------------------------------------------|
| `secure` (default) | Enables `zeroize` + `ct-eq` — secure memory wiping and constant-time equality (recommended) |
| `zeroize` | Memory zeroing on drop + opt-in safe cloning (requires `zeroize` crate) |
| `ct-eq` | Constant-time equality checks to prevent timing attacks (requires `subtle` crate) |
| `hash-eq` | Fast hash-based equality (BLAKE3 hashing with constant-time hash comparison, requires `blake3` and `ct-eq`) |
| `cloneable` | Opt-in safe cloning wrappers and `CloneableType` marker (requires `zeroize`) |
| `encoding` | All encoding support (`encoding-base64`, `encoding-bech32`, `encoding-hex`) |
| `encoding-base64` | Base64 encoding/decoding + constructors (requires `base64` crate) |
| `encoding-bech32` | Bech32 encoding/decoding + constructors (requires `bech32` crate) |
| `encoding-hex` | Hex encoding/decoding + constructors (requires `hex` crate) |
| `rand` | Secure random generation (`from_random()`) (requires `rand` crate) |
| `serde` | Meta-feature enabling both `serde-deserialize` and `serde-serialize` |
<<<<<<< Updated upstream
| `serde-deserialize` | Serde `Deserialize` support for loading secrets (requires `serde` crate) |
| `serde-serialize` | Serde `Serialize` support (gated by `SerializableType` marker) (requires `serde` crate) |
| `full` | Meta-feature enabling `secure`, `encoding`, `hash-eq`, and `cloneable` features |
=======
| `full` | Meta-feature enabling all optional features (includes `secure`) |
| `insecure` | Explicit opt-out for no-default-features builds (disables `zeroize` and `ct-eq`) — **not recommended** for production |
=======
| Feature              | Description                                                                                          |
|----------------------|------------------------------------------------------------------------------------------------------|
| `secure` (default)   | Enables `zeroize` + `ct-eq` — secure memory wiping and constant-time equality (recommended)         |
| `zeroize`            | Memory zeroing on drop + opt-in safe cloning (requires `zeroize` crate)                              |
| `ct-eq`              | Constant-time equality checks to prevent timing attacks (requires `subtle` crate)                   |
| `hash-eq`            | Fast hash-based equality (BLAKE3 hashing with constant-time hash comparison, requires `blake3` and `ct-eq`) |
| `cloneable`          | Opt-in safe cloning wrappers and `CloneableType` marker (requires `zeroize`)                         |
| `encoding`           | All encoding support (`encoding-base64`, `encoding-bech32`, `encoding-hex`)                          |
| `encoding-base64`    | Base64 encoding/decoding + constructors (requires `base64` crate)                                    |
| `encoding-bech32`    | Bech32 encoding/decoding + constructors (requires `bech32` crate)                                    |
| `encoding-hex`       | Hex encoding/decoding + constructors (requires `hex` crate)                                          |
| `rand`               | Secure random generation (`from_random()`) (requires `rand` crate)                                   |
| `serde`              | Meta-feature enabling both `serde-deserialize` and `serde-serialize`                                 |
| `serde-deserialize`  | Serde `Deserialize` support for loading secrets (requires `serde` crate)                             |
| `serde-serialize`    | Serde `Serialize` support (gated by `SerializableType` marker) (requires `serde` crate)             |
| `full`               | Meta-feature enabling `secure`, `encoding`, `hash-eq`, and `cloneable` features                      |
>>>>>>> Stashed changes
>>>>>>> Stashed changes

`no_std` + `alloc` compatible. Features add no overhead when unused.

## Security Model & Design Philosophy
`secure-gate` prioritizes **auditability** and **explicitness** over implicit convenience.

All secret access requires an explicit `.expose_secret()` (or `.expose_secret_mut()`) call — making exposures grep-able and preventing hidden leaks.

These calls are zero-cost `#[inline(always)]` reborrows (fully elided by the optimizer). The explicitness is deliberate for humans and auditors, with **no runtime overhead**.

## Quick Start
```rust
use secure_gate::{fixed_alias, dynamic_alias, ExposeSecret, ExposeSecretMut};

// Recommended: semantic aliases for clarity
<<<<<<< Updated upstream
fixed_alias!(pub Aes256Key, 32); // Fixed<[u8; 32]>
dynamic_alias!(pub Password, String); // Dynamic<String>
=======
<<<<<<< Updated upstream
fixed_alias!(pub Aes256Key, 32); // Fixed-size byte secret
dynamic_alias!(pub Password, String); // Heap string secret
=======
fixed_alias!(pub Aes256Key, 32);     // Fixed<[u8; 32]>
dynamic_alias!(pub Password, String); // Dynamic<String>
>>>>>>> Stashed changes
>>>>>>> Stashed changes

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
- `SecureEncoding`: Extension for string encoding (requires encoding features)

### Usage Example
<<<<<<< Updated upstream
=======
<<<<<<< Updated upstream
=======

```rust
use secure_gate::{Fixed, Dynamic, ExposeSecret};
>>>>>>> Stashed changes

>>>>>>> Stashed changes
```rust
use secure_gate::{Fixed, Dynamic, ExposeSecret};

let fixed_secret: Fixed<[u8; 32]> = [0u8; 32].into();
let fixed_len = fixed_secret.expose_secret().len();

let dynamic_secret: Dynamic<String> = "secret".into();
let dynamic_len = dynamic_secret.expose_secret().len();
```

<<<<<<< Updated upstream
## Random Generation (`rand` feature)
=======
<<<<<<< Updated upstream
### Trait Reference

| Trait | Required Features | Access Level | Core Types | Random Types | Encoding Types |
|-------|-------------------|--------------|------------|--------------|----------------|
| `ExposeSecret` | None | Read-only | ✓ | ✓ | ✓ |
| `ExposeSecretMut` | None | Read + Write | ✓ | ❌ | ❌ |
| `SecureRandom` | `rand` | Random + metadata | ❌ | ✓ | ❌ |

## Opt-In Safe Cloning

Cloning secret data is **opt-in** and **only available** when the `zeroize` feature is enabled.

This ensures cloning is deliberate, auditable, and always paired with secure zeroization.

**Key mechanism**: The `CloneSafe` marker trait.

To enable safe cloning:
1. Implement or derive `Clone`
2. Implement or derive `Zeroize`
3. Implement `CloneSafe` (blanket implementations exist for primitives and fixed arrays)

This prevents accidental deep copies that could bypass zeroization.

### Pre-Built Cloneable Types

| Type | Allocation | Inner Data | Typical Use Case |
|---------------------------------|------------|-----------------|-----------------------------------|
| `CloneableArray<const N: usize>`| Stack | `[u8; N]` | Fixed-size keys, nonces |
| `CloneableString` | Heap | `String` | Passwords, tokens, API keys |
| `CloneableVec` | Heap | `Vec<u8>` | Variable-length binary secrets |

```rust
#[cfg(feature = "zeroize")]
use secure_gate::{CloneableArray, CloneableString, CloneableVec};

#[cfg(feature = "zeroize")]
{
    let key: CloneableArray<32> = [0u8; 32].into();
    let pw: CloneableString = "hunter2".into();
    let seed: CloneableVec = vec![0u8; 64].into();

    let key2 = key.clone(); // Safe deep clone
    let pw2 = pw.clone();
}
```

### Recommended: Semantic Aliases

```rust
#[cfg(feature = "zeroize")]
use secure_gate::{CloneableArray, CloneableString};

#[cfg(feature = "zeroize")]
{
    pub type CloneablePassword = CloneableString;
    pub type CloneableMasterKey = CloneableArray<32>;
}
```

### Minimizing Stack Exposure

Use `init_with` / `try_init_with` when reading from untrusted sources:

```rust
#[cfg(feature = "zeroize")]
use secure_gate::CloneableString;

#[cfg(feature = "zeroize")]
{
    let pw = CloneableString::init_with(|| "hunter2".to_string());
    // Temporary zeroized immediately
}
```

### Custom Cloneable Types

**Note**: Custom implementations of `CloneSafe` are possible but discouraged — stick to the pre-baked `CloneableArray`, `CloneableString`, or `CloneableVec` types unless you have a strong justification. Improper impls can undermine the crate's cloning guarantees.

```rust
#[cfg(feature = "zeroize")]
use secure_gate::CloneSafe;

#[cfg(feature = "zeroize")]
{
    use zeroize::Zeroize;

    #[derive(Clone, Zeroize)]
    struct MyKey([u8; 32]);

    impl CloneSafe for MyKey {} // Enables safe cloning

    let key = MyKey([42u8; 32]);
    let key_copy = key.clone();
}
```

## Random Generation
=======
## Random Generation (`rand` feature)
>>>>>>> Stashed changes

>>>>>>> Stashed changes
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

<<<<<<< Updated upstream
`from_random()` uses system entropy (OsRng) — guaranteed cryptographically secure randomness. Panics on RNG failure (fail-fast for crypto code).

## Encoding (`encoding-*` features)
Outbound encoding uses the `SecureEncoding` trait (returns `String`):
=======
<<<<<<< Updated upstream
`FixedRandom<N>` can only be constructed via a cryptographically secure RNG.

Direct generation is also available:

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{Fixed, Dynamic};

    let key: Fixed<[u8; 32]> = Fixed::generate_random();
    let random: Dynamic<Vec<u8>> = Dynamic::generate_random(64);
}
```

## Encoding

=======
`from_random()` uses system entropy (`OsRng`) — guaranteed cryptographically secure randomness. Panics on RNG failure (fail-fast for crypto code).

## Encoding (`encoding-*` features)

Outbound encoding uses the `SecureEncoding` trait (returns `String`):

>>>>>>> Stashed changes
>>>>>>> Stashed changes
```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::{Fixed, SecureEncoding, ExposeSecret};

<<<<<<< Updated upstream
    let secret: Fixed<[u8; 16]> = [0u8; 16].into();

    let hex = secret.expose_secret().to_hex(); // String: "000000..."
    let hex_upper = secret.expose_secret().to_hex_upper(); // "000000..."
=======
<<<<<<< Updated upstream
    // Validation of an existing hex string
    let validated = HexString::new("deadbeef".to_string()).expect("valid hex");
    let decoded = validated.decode_into_bytes();
=======
    let secret: Fixed<[u8; 16]> = [0u8; 16].into();

    let hex = secret.expose_secret().to_hex();         // String: "000000..."
    let hex_upper = secret.expose_secret().to_hex_upper(); // "000000..."
>>>>>>> Stashed changes
>>>>>>> Stashed changes
}

#[cfg(feature = "encoding-base64")]
{
    use secure_gate::SecureEncoding;

    let bytes = b"Hello".as_slice();
    let base64 = bytes.to_base64url(); // "SGVsbG8"
}

#[cfg(feature = "encoding-bech32")]
{
<<<<<<< Updated upstream
    use secure_gate::SecureEncoding;
=======
    use secure_gate::{SecureEncoding, ExposeSecret};
    use secure_gate::encoding::bech32::Bech32String;
    
    let bytes = b"hello".as_slice();
<<<<<<< Updated upstream
    let bech32 = bytes.try_to_bech32("bc").expect("bech32 encoding failed");
    let bech32m = bytes.try_to_bech32m("tb").expect("bech32m encoding failed");
>>>>>>> Stashed changes

    let bytes = b"hello".as_slice();
    let bech32 = bytes.to_bech32("bc"); // panics on error
    let bech32m = bytes.to_bech32m("tb"); // panics on error
}
```

<<<<<<< Updated upstream
Inbound decoding via direct constructors (panic on invalid):
=======
Encoding requires explicit `.expose_secret()` when starting from a wrapped secret. Invalid inputs to `.new()` are zeroed when `zeroize` is enabled.
=======
    let bech32 = bytes.to_bech32("bc");   // panics on error
    let bech32m = bytes.to_bech32m("tb"); // panics on error
}
```

Inbound decoding via direct constructors (panic on invalid):

>>>>>>> Stashed changes
```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::Dynamic;
<<<<<<< Updated upstream
=======
>>>>>>> Stashed changes
>>>>>>> Stashed changes

    let key = Dynamic::<Vec<u8>>::from_hex("deadbeefdeadbeefdeadbeefdeadbeef");
}

<<<<<<< Updated upstream
=======
<<<<<<< Updated upstream
=======
>>>>>>> Stashed changes
#[cfg(feature = "encoding-base64")]
{
    use secure_gate::Dynamic;

    let data = Dynamic::<Vec<u8>>::from_base64("SGVsbG8");
}

#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::Dynamic;

    let data = Dynamic::<Vec<u8>>::from_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc");
}
```

## Constant-Time Equality (`ct-eq` feature)
<<<<<<< Updated upstream
=======

>>>>>>> Stashed changes
>>>>>>> Stashed changes
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

<<<<<<< Updated upstream
## Hash-Based Equality (`hash-eq` feature)
=======
<<<<<<< Updated upstream
Available on `Fixed<[u8; N]>` and `Dynamic<T>` where `T: AsRef<[u8]>`.

## Serde Support

⚠️ **Security Warning**: Serialization can permanently expose secrets. Only use for secure, trusted contexts (e.g., encrypted config files). Prefer encoded forms. Audit all opt-ins with `grep -r "SerializableSecret\|Exportable"`.

Load secrets from JSON/TOML/YAML or serialize raw secrets with explicit opt-in via `Exportable*` types (requires `"serde-serialize"`):
=======
## Hash-Based Equality (`hash-eq` feature)
>>>>>>> Stashed changes

>>>>>>> Stashed changes
```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::Fixed;

    let a: Fixed<[u8; 32]> = [0u8; 32].into();
    let b: Fixed<[u8; 32]> = [1u8; 32].into();

    assert!(a == a);
    assert!(a != b);
}
```

<<<<<<< Updated upstream
## Opt-In Safe Cloning (`cloneable` feature)
Cloning is opt-in via `CloneableType` marker and convenience macros.
=======
<<<<<<< Updated upstream
### Security Considerations
- **Deserialize** (`serde-deserialize`): Loads from trusted sources; invalid inputs zeroized if `zeroize` enabled
- **Serialize** (`serde-serialize`): Raw secrets only via `Exportable*` (opt-in). No direct Serialize on encoded/core types to prevent leaks
- **Exportable* types**: Deliberate conversions for raw output; no encoded auto-leakage
- **Audit points**: Grep for `Exportable*`, `SerializableSecret`, `fixed_exportable_alias!`, `dynamic_exportable_alias!`
- **No accidental exfiltration**: Encoded types serialize only encoded strings (manual); raw requires export
- **Zeroize on errors**: Invalid deserializes are wiped if `zeroize` enabled

## Macros

All macros require explicit visibility (e.g., `pub`, `pub(crate)`, or none for private).
=======
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
>>>>>>> Stashed changes

### Basic Aliases
>>>>>>> Stashed changes

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

    let key2 = key.clone(); // Safe deep clone
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
<<<<<<< Updated upstream

=======
<<<<<<< Updated upstream
>>>>>>> Stashed changes
fixed_alias!(pub Aes256Key, 32); // Fixed<[u8; 32]>
=======

fixed_alias!(pub Aes256Key, 32);     // Fixed<[u8; 32]>
>>>>>>> Stashed changes
dynamic_alias!(pub Password, String); // Dynamic<String>
```

With custom documentation:
```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub ApiKey, 32, "API key for service authentication");
dynamic_alias!(pub Token, Vec<u8>, "OAuth access token");
```

### Generic Aliases
<<<<<<< Updated upstream
=======

<<<<<<< Updated upstream
For reusable or library-provided secret types:

=======
>>>>>>> Stashed changes
>>>>>>> Stashed changes
```rust
use secure_gate::{fixed_generic_alias, dynamic_generic_alias};

fixed_generic_alias!(pub GenericFixedBuffer);
dynamic_generic_alias!(pub GenericHeapSecret, Vec<u8>);
```

## Memory Guarantees (`zeroize` enabled)
<<<<<<< Updated upstream
=======

<<<<<<< Updated upstream
>>>>>>> Stashed changes
| Type | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes |
|-----------------------|------------|-----------|-----------|------------------|--------------------------------------------|
| `Fixed<T>` | Stack | Yes | Yes | Yes (no heap) | - |
| `Dynamic<T>` | Heap | Yes | Yes | Yes | Full capacity wiped on drop |
<<<<<<< Updated upstream
=======
| `FixedRandom<N>` | Stack | Yes | Yes | Yes | - |
| `DynamicRandom` | Heap | Yes | Yes | Yes | - |
| `HexString` | Heap | Yes (invalid input) | Yes | Yes | Validated hex |
| `Base64String` | Heap | Yes (invalid input) | Yes | Yes | Validated base64 |
| `Bech32String` | Heap | Yes (invalid input) | Yes | Yes | Validated Bech32/Bech32m |

* Full capacity wiping (including slack) is performed by the `zeroize` crate:  
  - For `Vec<T>`: “Best effort” zeroization for Vec. Ensures the entire capacity of the Vec is zeroed. Cannot ensure that previous reallocations did not leave values on the heap. ([docs](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html#impl-Zeroize-for-Vec%3CZ%3E))  
  - For `String`: “Best effort” zeroization for String. Clears the entire capacity of the String. Cannot ensure that previous reallocations did not leave values on the heap. ([docs](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html#impl-Zeroize-for-String))
=======
| Type          | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes                  |
|---------------|------------|-----------|-----------|------------------|------------------------|
| `Fixed<T>`    | Stack      | Yes       | Yes       | Yes (no heap)    | —                      |
| `Dynamic<T>`  | Heap       | Yes       | Yes       | Yes              | Full capacity wiped on drop |
>>>>>>> Stashed changes
>>>>>>> Stashed changes

## Performance
The wrappers add no runtime overhead compared to raw types in benchmarks.

## Security
For in-depth security analysis, see [SECURITY.md](SECURITY.md).

## License
<<<<<<< Updated upstream
=======

<<<<<<< Updated upstream
>>>>>>> Stashed changes
MIT OR Apache-2.0
=======
MIT OR Apache-2.0
>>>>>>> Stashed changes
