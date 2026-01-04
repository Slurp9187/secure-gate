# secure-gate
`no_std`-compatible wrappers for sensitive data with explicit exposure requirements.
- `Fixed<T>` — Stack-allocated wrapper
- `Dynamic<T>` — Heap-allocated wrapper
- `FixedRng<N>` — Cryptographically secure random bytes of fixed length N
- `DynamicRng` — Heap-allocated cryptographically secure random bytes
- `HexString` — Validated lowercase hexadecimal string wrapper
- `Base64String` — Validated URL-safe base64 string wrapper (no padding)
- `Bech32String` — Validated Bech32 string wrapper (for age keys, etc.)

With the `zeroize` feature enabled, memory containing secrets is zeroed on drop, including spare capacity where applicable.

Access to secret data requires an explicit `.expose_secret()` call. There are no `Deref` implementations or other implicit access paths.

Cloning is opt-in via the `CloneableSecret` trait.

## Installation
```toml
[dependencies]
secure-gate = "0.7.2.rc.2"
```

Recommended configuration:
```toml
secure-gate = { version = "0.7.2.rc.2", features = ["full"] }
```

## Features
| Feature            | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `zeroize`          | Memory zeroing on drop and opt-in cloning via `CloneableSecret`             |
| `rand`             | Random generation (`FixedRng<N>::generate()`, `DynamicRng::generate()`)    |
| `ct-eq`            | Constant-time equality comparison                                           |
| `encoding`         | All encoding support (`encoding-hex`, `encoding-base64`, `encoding-bech32`)|
| `encoding-hex`     | Hex encoding, `HexString`, `FixedRng` hex methods                           |
| `encoding-base64`  | `Base64String`                                                              |
| `encoding-bech32`  | `Bech32String` (age-compatible Bech32 keys)                                 |
| `full`             | All optional features                                                       |

The crate is `no_std`-compatible with `alloc`. Features are optional and add no overhead when unused.

## Quick Start
```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub Aes256Key, 32);
dynamic_alias!(pub Password, String);

let pw: Password = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");

#[cfg(feature = "zeroize")]
{
    let key1: Aes256Key = Aes256Key::new([0u8; 32]);
    let key2 = key1.clone();
}

#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;
    fixed_alias_rng!(pub MasterKey, 32);
    fixed_alias_rng!(pub Nonce, 24);

    let key = MasterKey::generate();
    let nonce = Nonce::generate();

    #[cfg(feature = "encoding-hex")]
    {
        let hex = key.into_hex();
        println!("key hex: {}", hex.expose_secret());
    }
}
```

## Opt-In Cloning
Cloning is not implemented by default. It is enabled only for types that implement `CloneableSecret` (requires the `zeroize` feature).
```rust
#[cfg(feature = "zeroize")]
{
    use secure_gate::{CloneableSecret, Fixed};

    let key1: Fixed<[u8; 32]> = Fixed::new([1u8; 32]);
    let key2 = key1.clone();

    #[derive(Clone, zeroize::Zeroize)]
    struct MyKey([u8; 16]);
    impl CloneableSecret for MyKey {}

    let my_key: Fixed<MyKey> = Fixed::new(MyKey([0u8; 16]));
    let copy = my_key.clone();
}
```
Blanket implementations exist for primitives and fixed-size arrays.

## Randomness
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
        let hex_code = code.into_hex();
        println!("Backup code: {}", hex_code.expose_secret());
    }
}
```
`FixedRng<N>` can only be constructed via cryptographically secure RNG.

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
    use secure_gate::{encoding::hex::HexString, encoding::SecureEncodingExt};

    let bytes = [0u8; 16];
    let hex: String = bytes.to_hex();
    let hex_upper: String = bytes.to_hex_upper();

    let validated = HexString::new("deadbeef".to_string()).unwrap();
    let decoded = validated.decode_secret_to_bytes();
}

#[cfg(feature = "encoding-base64")]
{
    use secure_gate::encoding::base64::Base64String;

    let validated = Base64String::new("SGVsbG8".to_string()).unwrap();
    let decoded = validated.decode_secret_to_bytes();
}

#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::encoding::bech32::Bech32String;

    // Example with a classic age secret key (uppercase accepted, stored lowercase)
    let validated = Bech32String::new(
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33".to_string()
    ).unwrap();

    let decoded = validated.decode_secret_to_bytes(); // raw key bytes
    assert_eq!(validated.hrp().as_str(), "age-secret-key-1");
    assert!(!validated.is_postquantum());
}
```
Encoding functions require explicit `.expose_secret()`. Invalid inputs to the `.new()` constructors are zeroed when the `zeroize` feature is enabled.

## Constant-Time Equality
```rust
#[cfg(feature = "ct-eq")]
{
    use secure_gate::Fixed;

    let a = Fixed::<[u8; 32]>::generate_random();
    let b = Fixed::<[u8; 32]>::generate_random();

    assert!(a.ct_eq(&a));
}
```
Available on `Fixed<[u8; N]>` and `Dynamic<T>` where `T: AsRef<[u8]>`.

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
| Type           | Allocation | Auto-zero           | Full wipe | Slack eliminated | Notes                  |
|----------------|------------|---------------------|-----------|------------------|------------------------|
| `Fixed<T>`     | Stack      | Yes                 | Yes       | Yes (no heap)    |                        |
| `Dynamic<T>`   | Heap       | Yes                 | Yes       | No (until drop)  | Use `shrink_to_fit()`  |
| `FixedRng<N>`  | Stack      | Yes                 | Yes       | Yes              |                        |
| `HexString`    | Heap       | Yes (invalid input) | Yes       | No (until drop)  | Validated hex          |
| `Base64String` | Heap       | Yes (invalid input) | Yes       | No (until drop)  | Validated base64       |
| `Bech32String` | Heap       | Yes (invalid input) | Yes       | No (until drop)  | Validated Bech32       |

## Performance
The wrappers add no runtime overhead compared to raw types in benchmarks.

## Changelog
[CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License
MIT OR Apache-2.0
