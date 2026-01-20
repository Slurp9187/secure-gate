# secure-gate Examples
This document provides a comprehensive menu of copy-paste-ready examples for `secure-gate`.
All examples are designed to compile with the latest version and demonstrate real-world use cases.
**Important Notes**
- All examples assume `secure-gate = { version = "0.7.0", features = ["full"] }` for maximum features (including `zeroize`, `ct-eq`, `rand`, `encoding`, `serde`).
- Adjust features as needed (e.g., minimal: no features for `no_std` core).
- Always audit `.expose_secret()` calls—they are the only access points.
- For production: Enable `"secure"` (default) for zeroize + constant-time eq.
- Core usage (no macros) is shown first in relevant sections; all macros are grouped in Section 10.
## Table of Contents
1. [Basic Secrets: Fixed (Stack) & Dynamic (Heap)](#basic-secrets-fixed-stack--dynamic-heap)
2. [Fixed (Stack) Byte Arrays (Keys, Nonces)](#fixed-stack-byte-arrays)
3. [Dynamic (Heap) Strings & Vectors](#dynamic-heap-strings--vectors)
4. [Opt-In Safe Cloning (Cloneable Types)](#opt-in-safe-cloning)
5. [Cryptographic Randomness (FixedRandom & DynamicRandom)](#cryptographic-randomness)
6. [Validated Encodings (Hex, Base64, Bech32)](#validated-encodings)
7. [Serde: Loading Secrets (Deserialize)](#serde-loading-secrets)
8. [Serde: Exporting Secrets (Serialize with Marker)](#serde-exporting-secrets)
9. [Polymorphic Traits (ExposeSecret, SecureRandom)](#polymorphic-traits)
10. [All Macros (with Options)](#all-macros-with-options)
## 1. Basic Secrets: Fixed (Stack) & Dynamic (Heap)
### Fixed (Stack) Secret (Immutable Access)
```rust
use secure_gate::{Fixed, ExposeSecret};
let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]); // Stack-allocated, zero-cost
// Immutable access (explicit, zero-cost)
let bytes = key.expose_secret();
assert_eq!(bytes.len(), 32);
```
**Use Case**: Read-only fixed-size secrets (e.g., hardcoded nonces). True stack allocation (no heap).
### Fixed (Stack) Secret (Mutable Access)
```rust
use secure_gate::{Fixed, ExposeSecret, ExposeSecretMut};
let mut key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
// Mutable access
key.expose_secret_mut()[0] = 0xFF;
assert_eq!(key.expose_secret()[0], 0xFF);
```
**Use Case**: Modifiable fixed-size secrets (e.g., counters).
### Dynamic (Heap) Secret (Immutable Access)
```rust
use secure_gate::{Dynamic, ExposeSecret};
let password: Dynamic<String> = "hunter2".into(); // Heap-allocated
// Immutable access
assert_eq!(password.expose_secret(), "hunter2");
```
**Use Case**: Read-only variable-length secrets (e.g., loaded tokens).
### Dynamic (Heap) Secret (Mutable Access)
```rust
use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};
let mut password: Dynamic<String> = "hunter2".into();
// Mutable access
password.expose_secret_mut().push('!');
assert_eq!(password.expose_secret(), "hunter2!");
```
**Use Case**: Modifiable variable-length secrets (e.g., appending to payloads).
## 2. Fixed (Stack) Byte Arrays (Keys, Nonces)
### Basic Construction & Immutable Access
```rust
use secure_gate::{Fixed, ExposeSecret};
let key: Fixed<[u8; 32]> = [0u8; 32].into(); // From array (zero-cost)
// Immutable access
let bytes = key.expose_secret();
assert_eq!(bytes.len(), 32);
```
**Use Case**: Simple fixed keys—read-only.
### Mutable Access
```rust
use secure_gate::{Fixed, ExposeSecret, ExposeSecretMut};
let mut nonce: Fixed<[u8; 24]> = [0u8; 24].into();
// Mutable access
nonce.expose_secret_mut()[0] = 0xAA;
assert_eq!(nonce.expose_secret()[0], 0xAA);
```
**Use Case**: Incrementing nonces.
### Fallible TryFrom Slice
```rust
use secure_gate::{Fixed, FromSliceError};
let slice = [0u8; 16];
let nonce: Result<Fixed<[u8; 16]>, FromSliceError> = Fixed::try_from(&slice[..]);
assert!(nonce.is_ok());
```
**Use Case**: Safe from untrusted slices.
## 3. Dynamic (Heap) Strings & Vectors
### Dynamic (Heap) String (Immutable)
```rust
use secure_gate::{Dynamic, ExposeSecret};
let token: Dynamic<String> = "api_token".into();
// Immutable access
assert_eq!(token.expose_secret(), "api_token");
```
**Use Case**: Read-only strings (e.g., tokens).
### Dynamic (Heap) String (Mutable)
```rust
use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};
let mut token: Dynamic<String> = "api_token".into();
// Mutable access
token.expose_secret_mut().push_str("_v2");
assert_eq!(token.expose_secret(), "api_token_v2");
```
**Use Case**: Building/modifying strings.
### Dynamic (Heap) Vector (Immutable)
```rust
use secure_gate::{Dynamic, ExposeSecret};
let payload: Dynamic<Vec<u8>> = vec![1u8; 64].into();
// Immutable access
assert_eq!(payload.expose_secret().len(), 64);
```
**Use Case**: Read-only binary data.
### Dynamic (Heap) Vector (Mutable)
```rust
use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};
let mut payload: Dynamic<Vec<u8>> = vec![1u8; 64].into();
// Mutable access
payload.expose_secret_mut().push(0xFF);
assert_eq!(payload.expose_secret()[64], 0xFF);
```
**Use Case**: Appending to payloads.
## 4. Opt-In Safe Cloning (Cloneable Types)
### Cloneable (Heap) String (Requires `zeroize`)
```rust
#[cfg(feature = "zeroize")]
{
    use secure_gate::{CloneableString, ExposeSecret};
    let pw: CloneableString = "secret".into();
    let pw_clone = pw.clone(); // Safe deep clone
    assert_eq!(pw_clone.expose_secret().0, "secret");
}
```
**Use Case**: Cloneable passwords/tokens.
### Cloneable (Heap) Vector (Mutable, Requires `zeroize`)
```rust
#[cfg(feature = "zeroize")]
{
    use secure_gate::{CloneableVec, ExposeSecret, ExposeSecretMut};
    let data: CloneableVec = vec![1u8; 128].into();
    let mut data_clone = data.clone();
    data_clone.expose_secret_mut().0.push(0xFF);
    assert_eq!(data_clone.expose_secret().0.len(), 129);
}
```
**Use Case**: Cloneable variable binary.
### Safe Init (Requires `zeroize`)
```rust
#[cfg(feature = "zeroize")]
{
    use secure_gate::CloneableString;
    let pw: Result<CloneableString, std::convert::Infallible> = CloneableString::try_init_with(|| Ok("from_input".to_string()));
}
```
**Use Case**: Minimal exposure from sources.
## 5. Cryptographic Randomness (FixedRandom & DynamicRandom)
### FixedRandom (Stack) (Requires `rand`)
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{FixedRandom, ExposeSecret};
    let key: FixedRandom<32> = FixedRandom::generate(); // Fresh stack key
    assert_eq!(key.expose_secret().len(), 32);
}
```
**Use Case**: Read-only random keys.
### DynamicRandom (Heap) (Requires `rand`)
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{DynamicRandom, ExposeSecret};
    let seed: DynamicRandom = DynamicRandom::generate(64);
    assert_eq!(seed.expose_secret().len(), 64);
}
```
**Use Case**: Variable random seeds.
### Direct Generation on Core Types
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::Fixed;
    let key: Fixed<[u8; 32]> = Fixed::generate_random();
}
```
**Use Case**: Convenience without separate type.
### Mutable Access
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::Fixed;
    let mut key: Fixed<[u8; 32]> = Fixed::generate_random();
}
```
## 6. Validated Encodings (Hex, Base64, Bech32)
### Hex Encoding (Immutable)
```rust
#[cfg(all(feature = "encoding-hex", feature = "rand"))]
{
    use secure_gate::{SecureEncoding, ExposeSecret, encoding::hex::HexString, Fixed};
    let key: Fixed<[u8; 32]> = Fixed::generate_random();
    let hex = key.expose_secret().to_hex(); // Immutable hex string
    assert_eq!(hex.expose_secret().len(), 64); // "deadbeef..." style
}
```
**Use Case**: Read-only encoded keys.
### Hex Encoding (Mutable – Rare, but Possible)
```rust
#[cfg(all(feature = "serde-serialize", feature = "encoding-hex", feature = "rand"))]
{
    use secure_gate::{SecureEncoding, ExposeSecret, ExposeSecretMut, encoding::hex::HexString, Fixed, ExportableString};
    use serde_json;
    let mut key: Fixed<[u8; 32]> = Fixed::generate_random();
    key.expose_secret_mut()[0] = 0xFF;
    let hex = key.expose_secret().to_hex();
    let exportable: ExportableString = hex.into();
    let json = serde_json::to_string(&exportable).unwrap(); // "\"modified_hex_string\""
}
```
**Use Case**: Modify then encode and serialize.
### Validation on Input
```rust
#[cfg(feature = "encoding-base64")]
{
    use secure_gate::encoding::base64::Base64String;
    let validated = Base64String::new("YWJj".to_string()).unwrap();
}
```
**Use Case**: Safe input acceptance.
## 7. Serde: Loading Secrets (Deserialize)
### Basic Loading
```rust
#[cfg(feature = "serde-deserialize")]
{
    use secure_gate::{Dynamic, Fixed};
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Config {
        api_key: Fixed<[u8; 32]>,
        password: Dynamic<String>,
    }
    let config: Config = serde_json::from_str(r#"{
        "api_key": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],
        "password": "secret"
    }"#).unwrap();
}
```
**Use Case**: Direct secure config load.
### Encoding Loading
```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
{
    use secure_gate::encoding::hex::HexString;
    let hex_key: HexString = serde_json::from_str(r#""deadbeef""#).unwrap(); // Validates
}
```
**Use Case**: Load encoded secrets.
## 8. Serde: Exporting Secrets (Serialize with Marker)
### Raw Export (With Marker)
```rust
#[cfg(feature = "serde-serialize")]
{
    use secure_gate::{Fixed, ExportableType};
    use serde::Serialize;
    struct MyKey([u8; 32]);
    impl Serialize for MyKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.0.serialize(serializer)
        }
    }
    impl ExportableType for MyKey {} // Explicit opt-in
    let key: Fixed<MyKey> = Fixed::new(MyKey([0u8; 32]));
    let json = serde_json::to_string(&key).unwrap();
}
```
**Use Case**: Byte array export.
### Encoding Export (With Marker)
```rust
#[cfg(all(feature = "serde-serialize", feature = "encoding-hex"))]
{
    use secure_gate::{encoding::hex::HexString, ExportableString};
    let hex = HexString::new("deadbeef".to_string()).unwrap();
    let exportable: ExportableString = hex.into();
    let json = serde_json::to_string(&exportable).unwrap(); // → "\"deadbeef\""
}
```
**Use Case**: Readable export.
## 9. Polymorphic Traits (ExposeSecret, SecureRandom)
### Generic Access
```rust
use secure_gate::{ExposeSecret, Fixed, Dynamic};
fn secret_len<S: ExposeSecret>(s: &S) -> usize {
    s.len() // Metadata without exposure
}
let fixed: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
let dynamic: Dynamic<String> = "test".into();
assert_eq!(secret_len(&fixed), 32);
assert_eq!(secret_len(&dynamic), 4);
```
**Use Case**: Generic utils.
### Random Polymorphism (Requires `rand`)
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{SecureRandom, FixedRandom};
    fn use_random<R: SecureRandom>(rand: &R) -> usize {
        rand.expose_secret().len()
    }
    let key = FixedRandom::<32>::generate();
    assert_eq!(use_random(&key), 32);
}
```
**Use Case**: Generic randomness handling.
## 10. All Macros (with Options)
### fixed_alias! - Fixed (Stack) Aliases
```rust
use secure_gate::fixed_alias;
fixed_alias!(pub Aes256Key, 32);
fixed_alias!(pub ApiKey, 32, "API key for external service"); // Custom doc
fixed_alias!(pub(crate) InternalKey, 64);
fixed_alias!(InternalNonce, 24); // Private
let key: Aes256Key = [0u8; 32].into();
let api_key: ApiKey = [0u8; 32].into();
```
### fixed_generic_alias! - Generic Fixed (Stack) Buffers
```rust
use secure_gate::fixed_generic_alias;
fixed_generic_alias!(pub SecureBuffer, "Generic fixed (stack) buffer");
fixed_generic_alias!(pub(crate) Buffer); // Default doc
let buffer32 = SecureBuffer::<32>::new([0u8; 32]);
```
### dynamic_alias! - Dynamic (Heap) Aliases
```rust
use secure_gate::dynamic_alias;
dynamic_alias!(pub Password, String);
dynamic_alias!(pub Token, Vec<u8>, "OAuth access token"); // Custom doc
dynamic_alias!(pub(crate) Payload, Vec<u8>);
dynamic_alias!(InternalToken, String); // Private
let pw: Password = "hunter2".into();
let token: Token = vec![0u8; 16].into();
```
### dynamic_generic_alias! - Generic Dynamic (Heap)
```rust
use secure_gate::dynamic_generic_alias;
dynamic_generic_alias!(pub SecureVec, Vec<u8>, "Generic heap payload");
dynamic_generic_alias!(pub(crate) Token, Vec<u8>); // Default doc
let vec: SecureVec = vec![0u8; 128].into();
```
### fixed_alias_random! - Random-Only Fixed Aliases (Requires `rand`)
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_random;
    fixed_alias_random!(pub MasterKey, 32);
    fixed_alias_random!(pub SessionKey, 32, "Random session key for auth"); // Custom doc
    fixed_alias_random!(pub(crate) SessionNonce, 24);
    fixed_alias_random!(InternalNonce, 24); // Private
    let master = MasterKey::generate();
    let session = SessionKey::generate();
}
```
### fixed_exportable_alias! - Fixed Exportable (Serializable) Aliases (Requires `serde-serialize`)
```rust
#[cfg(feature = "serde-serialize")]
{
    use secure_gate::{fixed_exportable_alias, Fixed};
    fixed_exportable_alias!(pub ExportableApiKey, 32);
    let key: Fixed<ExportableApiKey> = Fixed::new(ExportableApiKey { inner: [0u8; 32] });
    // Can be serialized with serde
}
```
```rust
#[cfg(feature = "serde-serialize")]
{
    use secure_gate::{fixed_exportable_alias, Fixed};
    fixed_exportable_alias!(pub ExportableKey, 32, "Serializable API key");
    let key: Fixed<ExportableKey> = Fixed::new(ExportableKey { inner: [0u8; 32] });
    // Can be serialized with serde
}
```
### dynamic_exportable_alias! - Dynamic Exportable (Serializable) Aliases (Requires `serde-serialize`)
```rust
#[cfg(feature = "serde-serialize")]
{
    use secure_gate::{dynamic_exportable_alias, Dynamic};
    dynamic_exportable_alias!(pub ExportablePassword, String);
    // Raw types
    let pw: Dynamic<ExportablePassword> = Dynamic::new(ExportablePassword::from("secret".to_string()));
    // Can be serialized with serde
}
```
```rust
#[cfg(feature = "serde-serialize")]
{
    use secure_gate::{dynamic_exportable_alias, Dynamic};
    dynamic_exportable_alias!(pub ExportableToken, Vec<u8>, "Serializable token");
    let token: Dynamic<ExportableToken> = Dynamic::new(ExportableToken::from(vec![0u8; 16]));
    // Can be serialized with serde
}
```
**Use Case**: Semantic + serializable types.
---
These examples should cover about 90-95% of real-world usage.
