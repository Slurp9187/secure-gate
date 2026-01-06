# secure-gate
`no_std`-compatible wrappers for sensitive data with explicit exposure requirements.
- `Fixed<T>` - Stack-allocated wrapper
- `Dynamic<T>` - Heap-allocated wrapper
- `FixedRng<N>` - Cryptographically secure random bytes of fixed length N
- `DynamicRng` - Heap-allocated cryptographically secure random bytes
- `CloneableArray<const N: usize>` - Cloneable fixed-size stack secret (`[u8; N]`)
- `CloneableString` - Cloneable heap-allocated text secret (`String`)
- `CloneableVec` - Cloneable heap-allocated binary secret (`Vec<u8>`)
- `HexString` - Validated lowercase hexadecimal string wrapper
- `Base64String` - Validated URL-safe base64 string wrapper (no padding)
- `Bech32String` - Validated Bech32/Bech32m string wrapper
  With the `zeroize` feature enabled, memory containing secrets is zeroed on drop, including spare capacity where applicable.
  Access to secret data requires an explicit `.expose_secret()` call. There are no `Deref` implementations or other implicit access paths.
  Cloning is opt-in and only available under the `zeroize` feature.
## Installation
```toml
[dependencies]
secure-gate = "0.7.0-rc.4"
```
Recommended configuration:
```toml
secure-gate = { version = "0.7.0-rc.4", features = ["full"] }
```
## Features
| Feature | Description |
|--------------------|-----------------------------------------------------------------------------|
| `zeroize` | Memory zeroing on drop and opt-in cloning via pre-baked cloneable types |
| `rand` | Random generation (`FixedRng<N>::generate()`, `DynamicRng::generate()`) |
| `ct-eq` | Constant-time equality comparison |
| `encoding` | All encoding support (`encoding-hex`, `encoding-base64`, `encoding-bech32`) |
| `encoding-hex` | Hex encoding, `HexString`, `FixedRng` hex methods |
| `encoding-base64` | `Base64String` |
| `encoding-bech32` | `Bech32String` (Bech32 and Bech32m variants; supports mixed-case input, stores lowercase) |
| `full` | All optional features |
The crate is `no_std`-compatible with `alloc`. Features are optional and add no overhead when unused.
## Security Model & Design Philosophy
`secure-gate` prioritizes **auditability** and explicitness over implicit convenience.
Every access to secret material - even inside the crate itself - goes through a method named `.expose_secret()` (or `.expose_secret_mut()`). This is deliberate:
- Makes every exposure site grep-able and obvious in code reviews
- Prevents accidental silent leaks or hidden bypasses
- Ensures consistent reasoning about secret lifetimes and memory handling
  These calls are `#[inline(always)] const fn` reborrows - the optimizer elides them completely. There is **zero runtime cost**.
  It's intentional "theatre" for humans and auditors, but free for the machine. Clarity of purpose wins over micro-optimizations.
## Quick Start
```rust
use secure_gate::{fixed_alias, dynamic_alias};
fixed_alias!(pub Aes256Key, 32);
dynamic_alias!(pub Password, String);
let pw: Password = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");
#[cfg(feature = "zeroize")]
{
    use secure_gate::{CloneableArray, CloneableString, CloneableVec};
    let key: CloneableArray<32> = [0u8; 32].into();
    let pw: CloneableString = "hunter2".into();
    let seed: CloneableVec = vec![0u8; 64].into();
    let key2 = key.clone();
    let pw2 = pw.clone();
    let seed2 = seed.clone();
}
#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;
    fixed_alias_rng!(pub MasterKey, 32);
    #[cfg(feature = "encoding-hex")]
    {
        let key = MasterKey::generate();
        let hex = key.into_hex();
        println!("key hex: {}", hex.expose_secret());
    }
    #[cfg(feature = "encoding-base64")]
    {
        let key = MasterKey::generate();
        let base64 = key.into_base64();
        println!("key base64: {}", base64.expose_secret());
    }
    #[cfg(feature = "encoding-bech32")]
    {
        let key1 = MasterKey::generate();
        let bech32 = key1.into_bech32("example");
        println!("key bech32: {}", bech32.expose_secret());
        let key2 = MasterKey::generate();
        let bech32m = key2.into_bech32m("example");
        println!("key bech32m: {}", bech32m.expose_secret());
    }
}
```
## Opt-In Cloning
Cloning is available **only** when the `zeroize` feature is enabled.
The crate provides three ready-to-use cloneable primitives (zero boilerplate):
| Type | Allocation | Inner Data | Typical Use Case |
|----------------------------------|------------|------------|-----------------------------------|
| `CloneableArray<const N: usize>` | Stack | `[u8; N]` | Fixed-size keys/nonces |
| `CloneableString` | Heap | `String` | Passwords, tokens, API keys |
| `CloneableVec` | Heap | `Vec<u8>` | Seeds, variable-length binary |
```rust
#[cfg(feature = "zeroize")]
{
    use secure_gate::{CloneableArray, CloneableString, CloneableVec};
    let key: CloneableArray<32> = [0u8; 32].into();
    let mut pw: CloneableString = "hunter2".into();
    let seed: CloneableVec = vec![0u8; 64].into();
    let key2 = key.clone(); // Safe deep clone
    let pw2 = pw.clone();
    let seed2 = seed.clone();
    // Convenience access to inner values
    pw.expose_inner_mut().push('!');
    assert_eq!(pw.expose_inner(), "hunter2!");
}
```
### Semantic Aliases (Recommended)
For better readability, create type aliases:
```rust
#[cfg(feature = "zeroize")]
{
    use secure_gate::{CloneableArray, CloneableString, CloneableVec};
    pub type CloneablePassword = CloneableString;
    pub type CloneableAes256Key = CloneableArray<32>;
    pub type CloneableSeed = CloneableVec;
}
```
These are zero-cost and make intent crystal clear.
### Minimizing Stack Exposure
When reading secrets from user input (e.g., passwords), use `init_with`/`try_init_with` to reduce temporary stack exposure:
```rust
#[cfg(feature = "zeroize")]
{
    use secure_gate::CloneableString;
    let pw = CloneableString::init_with(|| {
        // Read from terminal, network, etc.
        "hunter2".to_string()
    });
    // Or fallible:
    let pw = CloneableString::try_init_with(|| {
        Ok::<String, &str>("hunter2".to_string())
    }).unwrap();
}
```
The temporary is cloned to the heap and zeroized immediately.
## Randomness
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;
    fixed_alias_rng!(pub JwtSigningKey, 32);
    fixed_alias_rng!(pub BackupCode, 16);
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

    // Bech32 (e.g., Bitcoin segwit)
    let bech32 = Bech32String::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string()).unwrap();
    assert!(bech32.is_bech32());

    // Bech32m (e.g., age keys)
    let bech32m = Bech32String::new("abc14w46h2at4w46h2at4w46h2at4w46h2at958ngu".to_string()).unwrap();
    assert!(bech32m.is_bech32m());
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
| Type | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes |
|-------------------|------------|-----------|-----------|------------------|------------------------|
| `Fixed<T>` | Stack | Yes | Yes | Yes (no heap) | |
| `Dynamic<T>` | Heap | Yes | Yes | No (until drop) | Use `shrink_to_fit()` |
| `FixedRng<N>` | Stack | Yes | Yes | Yes | |
| `HexString` | Heap | Yes (invalid input) | Yes | No (until drop) | Validated hex |
| `Base64String` | Heap | Yes (invalid input) | Yes | No (until drop) | Validated base64 |
| `Bech32String` | Heap | Yes (invalid input) | Yes | No (until drop) | Validated Bech32/Bech32m |
## Performance
The wrappers add no runtime overhead compared to raw types in benchmarks.
## Changelog
[[CHANGELOG.md]](https://github.com/Slurp9187/secure-gate/blob/v070rc/CHANGELOG.md)
## License
MIT OR Apache-2.0
