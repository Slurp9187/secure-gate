# secure-gate
`no_std`-compatible wrappers for sensitive data with explicit exposure requirements.

> **Note**: This crate is in active development and has not undergone independent security audit. Please review it for your use case and handle sensitive data with care.

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
secure-gate = "0.7.0-rc.7"
```

Basic configuration includes `zeroize` and `ct-eq` (via the `secure` meta-feature) for secure memory handling and constant-time equality.

**Recommended for most users** (secure defaults):
```toml
secure-gate = "0.7.0-rc.7" # default enables "secure"
```

**Batteries-included** (all optional features):
```toml
secure-gate = { version = "0.7.0-rc.7", features = ["full"] }
```

**Constrained / minimal builds** (no zeroization or ct-eq — **strongly discouraged** for production):
```toml
secure-gate = { version = "0.7.0-rc.7", default-features = false, features = ["insecure"] }
```

## Features

| Feature       | Description                                                                                          |
|---------------|------------------------------------------------------------------------------------------------------|
| `secure` (default) | Enables `zeroize` + `ct-eq` — secure memory wiping and constant-time equality (recommended)         |
| `zeroize`     | Memory zeroing on drop + opt-in safe cloning (requires `zeroize` crate)                             |
| `ct-eq`       | Constant-time equality checks to prevent timing attacks (requires `subtle` crate)                   |
| `rand`        | Random generation (`FixedRandom<N>::generate()`, `DynamicRandom::generate()`)                       |
| `encoding`    | All encoding support (`encoding-hex`, `encoding-base64`, `encoding-bech32`)                         |
| `encoding-hex`| Hex encoding + `HexString` + random hex methods                                                     |
| `encoding-base64` | `Base64String` (URL-safe, no padding)                                                             |
| `encoding-bech32` | `Bech32String` (Bech32/Bech32m, mixed-case input, lowercase storage)                             |
| `full`        | Meta-feature enabling all optional features (includes `secure`)                                    |
| `insecure`    | Explicit opt-out for no-default-features builds (disables `zeroize` and `ct-eq`) — **not recommended** for production |

`no_std` + `alloc` compatible. Features add no overhead when unused.

## Security Model & Design Philosophy

`secure-gate` prioritizes **auditability** and **explicitness** over implicit convenience.

All secret access requires an explicit `.expose_secret()` (or `.expose_secret_mut()`) call — making exposures grep-able and preventing hidden leaks.  

These calls are zero-cost `#[inline(always)]` reborrows (fully elided by the optimizer). The explicitness is deliberate "theater" for humans and auditors, with **no runtime overhead**.

## Quick Start

```rust
use secure_gate::{fixed_alias, dynamic_alias};

// Recommended: semantic aliases for clarity
fixed_alias!(pub Aes256Key, 32);          // Fixed-size byte secret
dynamic_alias!(pub Password, String);     // Heap string secret

// Create secrets
let key: Aes256Key = [0u8; 32].into();           // From array/slice
let mut pw: Password = "hunter2".into();         // From &str/String

// Access (zero-cost)
assert_eq!(pw.expose_secret(), "hunter2");
let key_bytes = key.expose_secret();             // &[u8; 32]

// Mutable access
pw.expose_secret_mut().push('!');

// See dedicated sections below for:
// - Opt-In Safe Cloning (`zeroize` feature)
// - Random Generation (`rand` feature)
// - Encoding (`encoding-*` features)
// - Constant-Time Equality (`ct-eq` feature)
```

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

| Type                            | Allocation | Inner Data      | Typical Use Case                  |
|---------------------------------|------------|-----------------|-----------------------------------|
| `CloneableArray<const N: usize>`| Stack      | `[u8; N]`       | Fixed-size keys, nonces           |
| `CloneableString`               | Heap       | `String`        | Passwords, tokens, API keys       |
| `CloneableVec`                  | Heap       | `Vec<u8>`       | Variable-length binary secrets    |

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
    use secure_gate::fixed_alias_random;

    fixed_alias_random!(pub JwtSigningKey, 32);
    fixed_alias_random!(pub BackupCode, 16);

    let key = JwtSigningKey::generate();

    #[cfg(feature = "encoding-hex")]
    {
        let code = BackupCode::generate();
        let hex_code = code.into_hex();
        println!("Backup code: {}", hex_code.expose_secret());
    }

    #[cfg(feature = "encoding-base64")]
    {
        let code = BackupCode::generate();
        let base64_code = code.into_base64();
        println!("Backup code: {}", base64_code.expose_secret());
    }
}
```

`FixedRandom<N>` can only be constructed via cryptographically secure RNG.

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
    use secure_gate::{encoding::hex::HexString, SecureEncodingExt};

    let bytes = [0u8; 16];
    let hex = bytes.to_hex();
    let hex_str = hex.expose_secret();
    let hex_upper: String = bytes.to_hex_upper();

    let validated = HexString::new("deadbeef".to_string()).unwrap();
    let decoded = validated.into_bytes();
}

#[cfg(feature = "encoding-base64")]
{
    use secure_gate::encoding::base64::Base64String;

    let validated = Base64String::new("SGVsbG8".to_string()).unwrap();
    let decoded = validated.into_bytes();
}

#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::encoding::bech32::Bech32String;

    let bech32 = Bech32String::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string()).unwrap();
    assert!(bech32.is_bech32());

    let bech32m = Bech32String::new("abc14w46h2at4w46h2at4w46h2at4w46h2at958ngu".to_string()).unwrap();
    assert!(bech32m.is_bech32m());
}
```

Encoding requires explicit `.expose_secret()`. Invalid inputs to `.new()` are zeroed when `zeroize` is enabled.

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

## Security Checklist

To maximize the security of your application when using `secure-gate`, adhere to these guidelines:

- **Use secure defaults**: Rely on the default feature set (`secure`) for automatic memory wiping (`zeroize`) and constant-time equality (`ct-eq`). Avoid `--no-default-features` unless you have a strong reason (e.g., constrained embedded environments).
- **Pre-validate encoding inputs**: For Bech32 and other encodings, validate inputs (e.g., HRPs) upfront. Use `try_*` methods (e.g., `try_to_bech32`) and handle errors properly to avoid issues from malformed data.
- **Prefer constant-time comparisons**: Use `.ct_eq()` for all sensitive equality checks to prevent timing attacks.
- **Minimize secret exposures**: Audit your code for `.expose_secret()` calls; keep them minimal, logged, and justified. Avoid unnecessary or prolonged exposures.
- **Restrict cloning**: Only clone when necessary. Prefer built-in `Cloneable*` types; be cautious with custom `CloneSafe` implementations.
- **Conservative feature usage**: Enable only the features you need (e.g., specific encodings) to reduce attack surface.
- **Regular review**: Periodically audit your secret handling logic, especially after dependency updates.

## Macros

All macros require explicit visibility (e.g., `pub`, `pub(crate)`, or none for private).

### Basic Aliases

```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub Aes256Key, 32);          // Fixed<[u8; 32]>
dynamic_alias!(pub Password, String);     // Dynamic<String>
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

These macros create type aliases to `Fixed<[u8; N]>`, `Dynamic<T>`, `FixedRandom<N>`, or their generic counterparts, inheriting all methods and security guarantees.

## Memory Guarantees (`zeroize` enabled)

| Type                  | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes                                      |
|-----------------------|------------|-----------|-----------|------------------|--------------------------------------------|
| `Fixed<T>`            | Stack      | Yes       | Yes       | Yes (no heap)    |                                            |
| `Dynamic<T>`          | Heap       | Yes       | Yes       | No (until drop)  | Use `shrink_to_fit()`                      |
| `FixedRandom<N>`      | Stack      | Yes       | Yes       | Yes              |                                            |
| `DynamicRandom`       | Heap       | Yes       | Yes       | No (until drop)  |                                            |
| `HexString`           | Heap       | Yes (invalid input) | Yes | No (until drop) | Validated hex                              |
| `Base64String`        | Heap       | Yes (invalid input) | Yes | No (until drop) | Validated base64                           |
| `Bech32String`        | Heap       | Yes (invalid input) | Yes | No (until drop) | Validated Bech32/Bech32m                   |

## Performance

Wrappers add no runtime overhead compared to raw types in benchmarks.

## Changelog

[CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License

MIT OR Apache-2.0
