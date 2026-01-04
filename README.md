# secure-gate

**Zero-cost, `no_std`-compatible wrappers for sensitive data with enforced explicit exposure.**

- `Fixed<T>` – Stack-allocated, zero-cost wrapper
- `Dynamic<T>` – Heap-allocated wrapper with full `.into()` ergonomics
- `FixedRng<N>` – Cryptographically secure random bytes of exact length N
- `DynamicRng` – Heap-allocated cryptographically secure random bytes
- `HexString` – Validated lowercase hex wrapper
- `Base64String` – Validated URL-safe base64 (no-pad) wrapper

When the `zeroize` feature is enabled, secrets are automatically wiped on drop (including spare capacity).

**All access to secret bytes requires an explicit `.expose_secret()` call** – no silent leaks, no `Deref`, no hidden methods.

Cloning is opt-in via the `CloneableSecret` trait, preventing accidental duplication of secrets.

## Installation

```toml
[dependencies]
secure-gate = "0.7.0"
```

**Recommended (maximum safety + ergonomics):**

```toml
secure-gate = { version = "0.7.0", features = ["full"] }
```

## Features

| Feature            | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `zeroize`          | Automatic memory wiping on drop + opt-in cloning via `CloneableSecret` – **strongly recommended** |
| `rand`             | RNG generation: `FixedRng<N>::generate()`, `DynamicRng::generate()`, fallible `try_generate()` |
| `ct-eq`            | `.ct_eq()` – constant-time equality comparison                             |
| `encoding`         | Encoding support (`encoding-hex` + `encoding-base64`)                       |
| `encoding-hex`     | `.to_hex()`, `.to_hex_upper()`, `HexString`, `FixedRng::into_hex()`        |
| `encoding-base64`  | `Base64String` (no `.to_base64url()` extension yet – use direct encoding)  |
| `full`             | All features above for batteries-included usage                             |

Works in `no_std` + `alloc`. Only pay for what you use.

## Quick Start

```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub Aes256Key, 32);     // Explicit visibility required
dynamic_alias!(pub Password, String); // Explicit visibility required

// Heap secrets – unchanged ergonomics
let pw: Password = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");

// Cloning is opt-in (requires zeroize feature)
#[cfg(feature = "zeroize")]
{
    let key1: Aes256Key = Aes256Key::new([0u8; 32]);
    let key2 = key1.clone(); // Works—arrays impl CloneableSecret by default
}

#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;

    fixed_alias_rng!(pub MasterKey, 32);
    fixed_alias_rng!(pub Nonce, 24);

    let key = MasterKey::generate(); // FixedRng<32>
    let nonce = Nonce::generate();   // FixedRng<24>

    #[cfg(feature = "encoding-hex")]
    {
        let hex = key.into_hex(); // Consumes key, zeroizes raw bytes
        println!("key hex: {}", hex.expose_secret());
    }
}
```

## Opt-In Cloning

Cloning is disabled by default to prevent accidental duplication. Enable it explicitly:

```rust
#[cfg(feature = "zeroize")]
{
    use secure_gate::{CloneableSecret, Fixed};

    // Primitives/arrays: Built-in CloneableSecret
    let key1: Fixed<[u8; 32]> = Fixed::new([1u8; 32]);
    let key2 = key1.clone(); // OK

    // Custom types: Opt-in manually
    #[derive(Clone, zeroize::Zeroize)]
    struct MyKey([u8; 16]);
    impl CloneableSecret for MyKey {}

    let my_key: Fixed<MyKey> = Fixed::new(MyKey([0u8; 16]));
    let copy = my_key.clone(); // OK
}
```

- **Why opt-in?** Prevents unsafe duplications. Only primitives/arrays get blanket impls.
- **Requires `zeroize`**: Ensures cloned copies are wiped on drop.

## Type-Safe Randomness

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;

    fixed_alias_rng!(pub JwtSigningKey, 32);
    fixed_alias_rng!(pub BackupCode, 16);

    let key = JwtSigningKey::generate();
    let code = BackupCode::generate();

    #[cfg(feature = "encoding-hex")]
    {
        let hex_code = code.into_hex(); // Raw bytes zeroized immediately
        println!("Backup code: {}", hex_code.expose_secret());
    }
}
```

- **Guaranteed freshness** – `FixedRng<N>` can only be constructed via secure RNG.
- **Zero-cost** – Newtype over `Fixed`, fully inlined.
- `.generate()` is the canonical constructor.

### Direct Random Generation

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{Fixed, Dynamic};
    let key: Fixed<[u8; 32]> = Fixed::generate_random();
    let random: Dynamic<Vec<u8>> = Dynamic::generate_random(64);
}
```

## Secure Encoding

```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::{encoding::hex::HexString, encoding::SecureEncodingExt};

    let bytes = [0u8; 16];
    let hex: String = bytes.to_hex();            // lowercase
    let hex_upper: String = bytes.to_hex_upper();

    let validated = HexString::new("deadbeef".to_string()).unwrap();
    let decoded = validated.to_bytes();
}

#[cfg(feature = "encoding-base64")]
{
    use secure_gate::encoding::base64::Base64String;

    let validated = Base64String::new("SGVsbG8".to_string()).unwrap();
    let decoded = validated.to_bytes();
}
```

- All encoding requires `.expose_secret()` on secret wrappers.
- `HexString`/`Base64String` validate input and zeroize on failure (with `zeroize`).

## Constant-Time Equality (`ct-eq`)

```rust
#[cfg(feature = "ct-eq")]
{
    use secure_gate::Fixed;
    let a = Fixed::<[u8; 32]>::generate_random();
    let b = Fixed::<[u8; 32]>::generate_random();
    assert!(a.ct_eq(&a));
}
```

Inherent `.ct_eq()` on `Fixed<[u8; N]>` and `Dynamic<T: AsRef<[u8]>>`.

## Macros

```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub Aes256Key, 32);
dynamic_alias!(pub Password, String);

#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;
    fixed_alias_rng!(pub MasterKey, 32);
}
```

## Memory Guarantees (`zeroize` enabled)

| Type            | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes                  |
|-----------------|------------|-----------|-----------|------------------|------------------------|
| `Fixed<T>`      | Stack      | Yes       | Yes       | Yes (no heap)    | Zero-cost              |
| `Dynamic<T>`    | Heap       | Yes       | Yes       | No (until drop)  | Use `shrink_to_fit()`  |
| `FixedRng<N>`   | Stack      | Yes       | Yes       | Yes              | Fresh + type-safe      |
| `HexString`     | Heap       | Yes (invalid) | Yes   | No (until drop)  | Validated hex          |
| `Base64String`  | Heap       | Yes (invalid) | Yes   | No (until drop)  | Validated base64       |

## Performance

Zero-cost wrappers. Benchmarks show no measurable overhead vs raw arrays.

## Changelog

[CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License

MIT OR Apache-2.0

---

**Explicit access, opt-in cloning, freshness guarantees—secure by design.**
