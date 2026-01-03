# secure-gate

**Zero-cost, `no_std`-compatible wrappers for sensitive data with enforced explicit exposure.**

- `Fixed<T>` – Stack-allocated, zero-cost wrapper
- `Dynamic<T>` – Heap-allocated wrapper with full `.into()` ergonomics
- `FixedRng<N>` – Cryptographically secure random bytes of exact length N
- `HexString` – Validated lowercase hex wrapper
- `Base64String` – Validated URL-safe base64 (no-pad) wrapper

When the `zeroize` feature is enabled, secrets are automatically wiped on drop (including spare capacity).  
**All access to secret bytes requires an explicit `.expose_secret()` call** – no silent leaks, no `Deref`, no hidden methods, no `into_inner()` bypasses.

Cloning is opt-in via the `CloneableSecret` trait, preventing accidental duplication of secrets.

## Installation
```toml
[dependencies]
secure-gate = "0.6.2"
```

**Recommended (maximum safety + ergonomics):**
```toml
secure-gate = { version = "0.6.2", features = ["zeroize", "rand", "encoding"] }
```

## Features
| Feature | Description |
|---------------|---------------------------------------------------------------------------------------------|
| `zeroize` | Automatic memory wiping on drop + opt-in cloning via `CloneableSecret` – **strongly recommended** |
| `rand` | RNG generation: `FixedRng<N>::generate()`, `DynamicRng::generate()`, fallible `try_generate()` |
| `ct-eq` | `.ct_eq()` – constant-time equality comparison |
| `encoding` | `.to_hex()`, `.to_hex_upper()`, `.to_base64url()` + `HexString`, `Base64String` |

Works in `no_std` + `alloc`. Only pay for what you use.

## Quick Start
```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub Aes256Key, 32);       // Explicit visibility required
dynamic_alias!(pub Password, String);   // Explicit visibility required

// Cloning is opt-in (requires zeroize feature)
#[cfg(feature = "zeroize")]
{
    let key1: Aes256Key = Aes256Key::new([0u8; 32]);
    let key2 = key1.clone();  // Works—arrays impl CloneableSecret by default
}

// Heap secrets – unchanged ergonomics
let pw: Password = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");

#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;

    fixed_alias_rng!(pub MasterKey, 32);  // Explicit visibility required
    fixed_alias_rng!(pub Nonce, 24);      // Explicit visibility required
    let key = MasterKey::generate();      // FixedRng<32>
    let nonce = Nonce::generate();        // FixedRng<24>

    // Hex encoding available via `FixedRng::generate().into_hex()`
}
```

## Opt-In Cloning
Cloning is disabled by default to prevent accidental duplication. Enable it explicitly:

```rust
#[cfg(feature = "zeroize")]
{
    use secure_gate::{CloneableSecret, Dynamic, Fixed};

    // Primitives/arrays: Built-in CloneableSecret
    let key1: Fixed<[u8; 32]> = Fixed::new([1u8; 32]);
    let key2 = key1.clone();  // ✅ OK—[u8; 32] is cloneable

    // Dynamic strings: Not cloneable by default
    let pw1: Dynamic<String> = Dynamic::new("secret".to_string());
    // let pw2 = pw1.clone();  // ❌ Compile error—String !impl CloneableSecret

    // Custom types: Opt-in manually
    #[derive(Clone, zeroize::Zeroize)]
    struct MyKey([u8; 16]);
    impl CloneableSecret for MyKey {}  // Enables cloning

    let my_key: Fixed<MyKey> = Fixed::new(MyKey([0u8; 16]));
    let copy = my_key.clone();  // ✅ OK—MyKey impls CloneableSecret
}
```

- **Why opt-in?** Prevents unsafe duplications (e.g., multiple copies in memory). Only primitives/arrays get blanket impls; dynamic types require explicit opt-in.
- **Requires `zeroize`**: Ensures cloned copies are wiped on drop.

## Type-Safe Randomness
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;

    fixed_alias_rng!(pub JwtSigningKey, 32);   // Explicit visibility required
    fixed_alias_rng!(pub BackupCode, 16);       // Explicit visibility required
    let key = JwtSigningKey::generate();        // FixedRng<32>
    let code = BackupCode::generate();          // FixedRng<16>

    #[cfg(feature = "encoding-hex")]
    {
        let hex_code = BackupCode::generate().into_hex();
        println!("Backup code: {}", hex_code.expose_secret());
    }
}
```

- **Guaranteed freshness** – `FixedRng<N>` can only be constructed via secure RNG.
- **Zero-cost** – Newtype over `Fixed`, fully inlined.
- **Explicit visibility** – All macros require clear visibility specification (`pub`, `pub(crate)`, or private)
- `.generate()` is the canonical constructor (`.new()` unavailable).

### Fallible RNG Generation
For non-panic scenarios:

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::random::{FixedRng, DynamicRng};
    use rand::rand_core::OsError;

    let key: Result<FixedRng<32>, OsError> = FixedRng::try_generate();
    let random: Result<DynamicRng, OsError> = DynamicRng::try_generate(64);
}
```

### Converting RNG Types
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{Fixed, Dynamic, random::{FixedRng, DynamicRng}};

    let key: Fixed<[u8; 32]> = FixedRng::<32>::generate().into();
    let random: Dynamic<Vec<u8>> = DynamicRng::generate(64).into();
}
```

### Direct Random Generation
```rust
use secure_gate::{Fixed, Dynamic};

#[cfg(feature = "rand")]
{
    let key: Fixed<[u8; 32]> = Fixed::generate_random();  // Fallible: Fixed::try_generate_random()
    let random: Dynamic<Vec<u8>> = Dynamic::generate_random(64);
}
```

**Note**: `FixedRng`/`DynamicRng` preserve the type-level guarantee that values came from RNG. Converting to `Fixed`/`Dynamic` loses that guarantee but enables mutation if needed.

## Secure Encoding – `encoding` feature
```rust
#[cfg(feature = "encoding")]
{
    use secure_gate::{HexString, Base64String, SecureEncodingExt};

    let bytes = [0u8; 16];
    let hex: String = bytes.to_hex();  // "0000..." (requires .expose_secret() on secrets)
    let b64: String = bytes.to_base64url();  // URL-safe, no padding

    let hex_str = HexString::new("deadbeef".to_string()).unwrap();  // Validates hex
    let decoded = hex_str.to_bytes();  // [222, 173, 190, 239]

    let b64_str = Base64String::new("SGVsbG8".to_string()).unwrap();  // Validates base64url
    let decoded_b64 = b64_str.to_bytes();  // [72, 101, 108, 108, 111]

    // Constant-time eq
    #[cfg(feature = "ct-eq")]
    {
        use secure_gate::eq::ConstantTimeEq;
        let same = bytes.ct_eq(&[1u8; 16]);  // False, constant-time
    }
}
```

- `HexString`/`Base64String`: Validated, zeroized on invalid input.
- All conversions require `.expose_secret()` for secret wrappers.
- `ct_eq()` independent via `ct-eq` feature.

## Fallible Construction (TryFrom)
For error-handling in strict environments:

```rust
use secure_gate::{Fixed, FromSliceError};

// Panics on mismatch (for backward compat)
let fixed: Fixed<[u8; 4]> = Fixed::from_slice(&[1u8, 2, 3, 4]);

// Returns Result on mismatch
let fixed: Fixed<[u8; 4]> = Fixed::<[u8; 4]>::try_from(&[1u8, 2, 3, 4] as &[u8]).unwrap();
let error: FromSliceError = Fixed::<[u8; 4]>::try_from(&[1u8, 2] as &[u8]).unwrap_err();
```

## Macros
```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub Aes256Key, 32);
fixed_alias!(private_key, 32);
fixed_alias!(pub(crate) InternalKey, 64);

dynamic_alias!(pub Password, String);

#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;
    fixed_alias_rng!(pub MasterKey, 32);
}
```

## Memory Guarantees (`zeroize` enabled)
| Type | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes |
|-----------------|------------|-----------|-----------|------------------|---------------------------|
| `Fixed<T>` | Stack | Yes | Yes | Yes (no heap) | Zero-cost |
| `Dynamic<T>` | Heap | Yes | Yes | No (until drop) | Use `expose_secret_mut().shrink_to_fit()` |
| `FixedRng<N>` | Stack | Yes | Yes | Yes | Fresh + type-safe |
| `HexString` | Heap | Yes (on invalid) | Yes | No (until drop) | Validated hex |
| `Base64String` | Heap | Yes (on invalid) | Yes | No (until drop) | Validated base64 |

## Performance
Zero-cost wrappers. Benchmarks show no measurable overhead vs raw arrays.

## Changelog
[CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License
MIT OR Apache-2.0

---
**Explicit access, opt-in cloning, fallible operations—secure by design.**