# secure-gate

`no_std`-compatible wrappers for sensitive data with explicit exposure requirements.

> 🔒 **Note**: This crate is in active development and ***has not undergone independent security audit***. Please review it for your use case and handle sensitive data with care.
> See [SECURITY.md](SECURITY.md) for detailed security considerations.

- `Fixed<T>` — Stack-allocated wrapper
- `Dynamic<T>` — Heap-allocated wrapper
- `FixedRandom<N>` — Stack-allocated cryptographically secure random bytes
- `DynamicRandom` — Heap-allocated cryptographically secure random bytes
- `CloneableArray<const N: usize>` — Cloneable fixed-size stack secret (`[u8; N]`)
- `CloneableString` — Cloneable heap-allocated text secret (`String`)
- `CloneableVec` — Cloneable heap-allocated binary secret (`Vec<u8>`)
- `HexString` — Validated lowercase hexadecimal string wrapper
- `Base64String` — Validated URL-safe base64 string wrapper (no padding)
- `Bech32String` — Validated Bech32/Bech32m string wrapper
 
Memory containing secrets is zeroed on drop, including spare capacity where applicable (when `zeroize` is enabled).

Access requires an explicit `.expose_secret()` (or `.expose_secret_mut()`) call — no `Deref` or implicit paths.

## Installation

```toml
[dependencies]
secure-gate = "0.7.0-rc.9"
```

Basic configuration includes `zeroize` and `ct-eq` (via the `secure` meta-feature) for secure memory handling and constant-time equality.

**Recommended for most users** (secure defaults):
```toml
secure-gate = "0.7.0-rc.9" # default enables "secure"
```

**Batteries-included** (all optional features):
```toml
secure-gate = { version = "0.7.0-rc.9", features = ["full"] }
```

**Constrained/minimal builds** (no zeroization or ct-eq — **strongly discouraged** for production):
```toml
secure-gate = { version = "0.7.0-rc.9", default-features = false, features = ["insecure"] }
```

## Features

| Feature | Description |
|---------------|------------------------------------------------------------------------------------------------------|
| `secure` (default) | Enables `zeroize` + `ct-eq` — secure memory wiping and constant-time equality (recommended) |
| `zeroize` | Memory zeroing on drop + opt-in safe cloning (requires `zeroize` crate) |
| `ct-eq` | Constant-time equality checks to prevent timing attacks (requires `subtle` crate) |
| `rand` | Random generation (`FixedRandom<N>::generate()`, `DynamicRandom::generate()`) |
| `encoding` | All encoding support (`encoding-hex`, `encoding-base64`, `encoding-bech32`) |
| `encoding-hex`| Hex encoding + `HexString` + random hex methods |
| `encoding-base64` | `Base64String` (URL-safe, no padding) |
| `encoding-bech32` | `Bech32String` (Bech32/Bech32m, mixed-case input, lowercase storage) |
| `serde-deserialize` | Serde `Deserialize` support for loading secrets |
| `serde-serialize` | Serde `Serialize` support (gated by `SerializableSecret` marker) |
| `serde` | Meta-feature enabling both `serde-deserialize` and `serde-serialize` |
| `full` | Meta-feature enabling all optional features (includes `secure`) |
| `insecure` | Explicit opt-out for no-default-features builds (disables `zeroize` and `ct-eq`) — **not recommended** for production |

`no_std` + `alloc` compatible. Features add no overhead when unused.

## Security Model & Design Philosophy

`secure-gate` prioritizes **auditability** and **explicitness** over implicit convenience.

All secret access requires an explicit `.expose_secret()` (or `.expose_secret_mut()`) call — making exposures grep-able and preventing hidden leaks.

These calls are zero-cost `#[inline(always)]` reborrows (fully elided by the optimizer). The explicitness is deliberate for humans and auditors, with **no runtime overhead**.

## Quick Start

```rust
use secure_gate::{fixed_alias, dynamic_alias, ExposeSecret, ExposeSecretMut};

// Recommended: semantic aliases for clarity
fixed_alias!(pub Aes256Key, 32); // Fixed-size byte secret
dynamic_alias!(pub Password, String); // Heap string secret

// Create secrets
let key: Aes256Key = [0u8; 32].into(); // From array/slice
let mut pw: Password = "hunter2".into(); // From &str or String

// Access (zero-cost)
assert_eq!(pw.expose_secret(), "hunter2");
let key_bytes = key.expose_secret(); // &[u8; 32]

// Mutable access
pw.expose_secret_mut().push('!');

// See dedicated sections below for:
// - Opt-In Safe Cloning (`zeroize` feature)
// - Random Generation (`rand` feature)
// - Encoding (`encoding-*` features)
// - Constant-Time Equality (`ct-eq` feature)
// - Serde Support (`serde` feature)
```

## Polymorphic Traits for Generic Operations

The `secure-gate` crate provides polymorphic traits that enable writing generic code across different secret wrapper types while maintaining security guarantees:
- `ExposeSecret` & `ExposeSecretMut`: Polymorphic secret access with controlled mutability
- `SecureRandom`: Combined random generation with metadata access (requires `rand` feature)

### Key Security Design

- **Full access**: Core wrappers (`Fixed`, `Dynamic`) implement `ExposeSecret` and `ExposeSecretMut` (read + write)
- **Read-only**: Random (`FixedRandom`, `DynamicRandom`) and encoding wrappers only implement `ExposeSecret` to prevent invalidation of cryptographic properties
- **Zero-cost**: All traits use `#[inline(always)]` for optimal performance
- **Type safety**: Polymorphic operations preserve wrapper invariants

### Usage Example

```rust
use secure_gate::{
    Fixed, Dynamic,
    ExposeSecret, ExposeSecretMut
};

#[cfg(feature = "rand")]
use secure_gate::FixedRandom;

// Check properties using expose_secret
let fixed_secret: Fixed<[u8; 32]> = [0u8; 32].into();
let fixed_len = fixed_secret.expose_secret().len();
let dynamic_secret: Dynamic<String> = "secret".into();
let dynamic_len = dynamic_secret.expose_secret().len();

#[cfg(feature = "rand")]
{
    let random_secret = FixedRandom::<16>::generate();
    let random_len = random_secret.expose_secret().len();
    // Use lengths as needed
}
```

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

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{fixed_alias_random, ExposeSecret};
    
    fixed_alias_random!(pub JwtSigningKey, 32);
    fixed_alias_random!(pub BackupCode, 16);

    let key = JwtSigningKey::generate();

    #[cfg(feature = "encoding-hex")]
    {
        let code = BackupCode::generate();
        let hex_code = code.into_hex();
        println!("Backup code (hex): {}", hex_code.expose_secret());
    }

    #[cfg(feature = "encoding-base64")]
    {
        let code = BackupCode::generate();
        let base64_code = code.into_base64url();
        println!("Backup code (base64url): {}", base64_code.expose_secret());
    }
}
```

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

```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::{fixed_alias, SecureEncoding, ExposeSecret};
    use secure_gate::encoding::hex::HexString;
    
    fixed_alias!(TestKey, 16);
    let secret: TestKey = [0u8; 16].into();
    
    // Explicit exposure before encoding (recommended pattern)
    let hex = secret.expose_secret().to_hex();
    let hex_str = hex.expose_secret();
    let hex_upper: String = secret.expose_secret().to_hex_upper();

    // Validation of an existing hex string
    let validated = HexString::new("deadbeef".to_string()).expect("valid hex");
    let decoded = validated.decode_into_bytes();
}

#[cfg(feature = "encoding-base64")]
{
    use secure_gate::{SecureEncoding, ExposeSecret, encoding::base64::Base64String};
    
    let bytes = b"Hello".as_slice();
    let base64 = bytes.to_base64url(); // URL-safe, no padding
    let validated = Base64String::new("SGVsbG8".to_string()).expect("valid base64"); // "Hello"
    let decoded = validated.decode_into_bytes();
}

#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::{SecureEncoding, ExposeSecret};
    use secure_gate::encoding::bech32::Bech32String;
    
    let bytes = b"hello".as_slice();
    let bech32 = bytes.try_to_bech32("bc").expect("bech32 encoding failed");
    let bech32m = bytes.try_to_bech32m("tb").expect("bech32m encoding failed");

    // Validation example
    let bech32_valid = Bech32String::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string()).expect("valid bech32");
    assert!(bech32_valid.is_bech32());
    let decoded_bech32 = bech32_valid.decode_into_bytes();
    
    let bech32m_valid = Bech32String::new("BC1P0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQZK5JJ0".to_string()).expect("valid bech32m");
    assert!(bech32m_valid.is_bech32m());
    let decoded_bech32m = bech32m_valid.decode_into_bytes();
}
```

Encoding requires explicit `.expose_secret()` when starting from a wrapped secret. Invalid inputs to `.new()` are zeroed when `zeroize` is enabled.

## Constant-Time Equality

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

Available on `Fixed<[u8; N]>` and `Dynamic<T>` where `T: AsRef<[u8]>`.

## Serde Support

Load secrets from JSON/TOML/YAML or serialize them with explicit opt-in via split features:

```rust
#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
{
    use secure_gate::{Fixed, SerializableSecret, ExposeSecret};
    use serde_json;

    // Deserialize (enabled with serde-deserialize)
    let secret: Fixed<[u8; 32]> = serde_json::from_str(r#"[1,2,3,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"#).unwrap();

    // Serialize (enabled with serde-serialize, gated by SerializableSecret marker - no blanket impls)
    // Define a newtype to avoid orphan rules in this example
    #[derive(serde::Deserialize, serde::Serialize)]
    struct MySecret([u8; 32]);
    impl SerializableSecret for MySecret {}

    let secret: Fixed<MySecret> = Fixed::new(MySecret([1u8; 32]));
    let json = serde_json::to_string(&secret).unwrap();

    // Cloneable types can serialize since their inners implement SerializableSecret
    let string_secret = secure_gate::CloneableString::from("password".to_string());
    let json_string = serde_json::to_string(&string_secret).unwrap();
}
```

### Security Considerations
- **Deserialize** (`serde-deserialize`): Loads from trusted sources only; invalid inputs are zeroized if `zeroize` enabled
- **Serialize** (`serde-serialize`): Requires explicit `SerializableSecret` impl for all types - grep for `SerializableSecret` to audit all serialization points; prevents accidental exfiltration
- **No automatic serialization**: No blanket implementations; even primitive types require explicit marking to prevent accidental leaks
- **No string/vector leaks**: String/vector secrets don't serialize by default (like `secrecy` crate)
- **Marker trait**: `SerializableSecret` ensures serialization is intentional and audited

## Macros

All macros require explicit visibility (e.g., `pub`, `pub(crate)`, or none for private).

### Basic Aliases

```rust
use secure_gate::{fixed_alias, dynamic_alias};
fixed_alias!(pub Aes256Key, 32); // Fixed<[u8; 32]>
dynamic_alias!(pub Password, String); // Dynamic<String>
```

With custom documentation:

```rust
use secure_gate::{fixed_alias, dynamic_alias};
fixed_alias!(pub ApiKey, 32, "API key for service authentication");
dynamic_alias!(pub Token, Vec<u8>, "OAuth access token");
```

### Generic Aliases

For reusable or library-provided secret types:

```rust
use secure_gate::{fixed_generic_alias, dynamic_generic_alias};

fixed_generic_alias!(pub GenericFixedBuffer);
dynamic_generic_alias!(pub GenericHeapSecret, Vec<u8>); // Vec<u8> can be any type
```

Custom doc strings (optional):

```rust
use secure_gate::{fixed_generic_alias, dynamic_generic_alias};

fixed_generic_alias!(pub SecureBuffer, "Generic fixed-size secret buffer");
dynamic_generic_alias!(pub SecureHeap, String, "Generic heap-allocated secret");
```

### Random-Only Fixed Aliases (`rand` feature)

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_random;

    fixed_alias_random!(pub MasterKey, 32); // FixedRandom<32>
}
```

With custom documentation:

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_random;

    fixed_alias_random!(pub SessionKey, 32, "Random session key for authentication");
}
```


These macros create type aliases to `Fixed<[u8; N]>`, `Dynamic<T>`, `FixedRandom<N>`, or their generic counterparts, inheriting all methods and security guarantees.

## Memory Guarantees (`zeroize` enabled)

| Type | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes |
|-----------------------|------------|-----------|-----------|------------------|--------------------------------------------|
| `Fixed<T>` | Stack | Yes | Yes | Yes (no heap) | - |
| `Dynamic<T>` | Heap | Yes | Yes | Yes | Full capacity wiped on drop |
| `FixedRandom<N>` | Stack | Yes | Yes | Yes | - |
| `DynamicRandom` | Heap | Yes | Yes | Yes | - |
| `HexString` | Heap | Yes (invalid input) | Yes | Yes | Validated hex |
| `Base64String` | Heap | Yes (invalid input) | Yes | Yes | Validated base64 |
| `Bech32String` | Heap | Yes (invalid input) | Yes | Yes | Validated Bech32/Bech32m |

* Full capacity wiping (including slack) is performed by the `zeroize` crate:  
  - For `Vec<T>`: “Best effort” zeroization for Vec. Ensures the entire capacity of the Vec is zeroed. Cannot ensure that previous reallocations did not leave values on the heap. ([docs](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html#impl-Zeroize-for-Vec%3CZ%3E))  
  - For `String`: “Best effort” zeroization for String. Clears the entire capacity of the String. Cannot ensure that previous reallocations did not leave values on the heap. ([docs](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html#impl-Zeroize-for-String))

## Performance

The wrappers add no runtime overhead compared to raw types in benchmarks.

## Security

For in-depth security analysis, see [SECURITY.md](SECURITY.md).

## Security Checklist

To maximize the security of your application when using `secure-gate`, adhere to these guidelines:

- **Use secure defaults**: Rely on the default feature set (`secure`) for automatic memory wiping (`zeroize`) and constant-time equality (`ct-eq`). Avoid `--no-default-features` unless you have a strong reason (e.g., constrained embedded environments).
- **Pre-validate encoding inputs**: For Bech32 and other encodings, validate inputs (e.g., HRPs) upfront. Use `try_*` methods (e.g., `try_to_bech32`) and handle errors properly to avoid issues from malformed data.
- **Prefer constant-time comparisons**: Use `.ct_eq()` for all sensitive equality checks to prevent timing attacks.
- **Minimize secret exposures**: Audit your code for `.expose_secret()` calls; keep them minimal, logged, and justified. Avoid unnecessary or prolonged exposures.
- **Restrict cloning**: Only clone when necessary. Prefer built-in `Cloneable*` types; be cautious with custom `CloneSafe` implementations.
- **Conservative feature usage**: Enable only the features you need (e.g., specific encodings) to reduce attack surface.
- **Explicitly mark serializable types**: Only implement `SerializableSecret` for types that must be serialized with `serde-serialize`; audit all impls during code reviews to prevent accidental exfiltration.
- **Regular review**: Periodically audit your secret handling logic, especially after dependency updates.
- **Security considerations**: Refer to [SECURITY.md](SECURITY.md) for detailed security considerations.

## Changelog

[CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License

MIT OR Apache-2.0
