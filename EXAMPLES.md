# secure-gate Examples

This document provides a comprehensive menu of copy-paste-ready examples for `secure-gate`.  
All examples are designed to compile with the latest version and demonstrate real-world use cases.

**Important Notes**
- All examples assume `secure-gate = { version = "0.7.0", features = ["full"] }` for maximum features (including `zeroize`, `ct-eq`, `rand`, `encoding`, `serde`).
- Adjust features as needed (e.g., minimal: no features for `no_std` core).
- Always audit `.expose_secret()` calls—they are the only access points.
- For production: Enable `"secure"` (default) for zeroize + constant-time eq.

## Table of Contents

1. [Basic Secrets (Fixed & Dynamic)](#basic-secrets)
2. [Fixed-Size Byte Arrays (Keys, Nonces)](#fixed-size-byte-arrays)
3. [Heap Strings & Vectors](#heap-strings--vectors)
4. [Opt-In Safe Cloning (Cloneable Types)](#opt-in-safe-cloning)
5. [Cryptographic Randomness (FixedRandom & DynamicRandom)](#cryptographic-randomness)
6. [Validated Encodings (Hex, Base64, Bech32)](#validated-encodings)
7. [Serde: Loading Secrets (Deserialize)](#serde-loading-secrets)
8. [Serde: Exporting Secrets (Serialize with Marker)](#serde-exporting-secrets)
9. [Polymorphic Traits (ExposeSecret, SecureRandom)](#polymorphic-traits)
10. [Advanced: Custom Types & Macros](#advanced-custom-types--macros)

## 1. Basic Secrets (Fixed & Dynamic)

### Fixed-Size Stack Secret (Zero-Cost)
```rust
use secure_gate::{Fixed, ExposeSecret};

let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);  // Stack-allocated

// Access (explicit, zero-cost)
let bytes = key.expose_secret();
assert_eq!(bytes.len(), 32);
```

**Use Case**: Cryptographic keys/nonces where size known at compile-time. True zero-cost when `zeroize` off.

### Heap Dynamic Secret (String/Vec)
```rust
use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};

let mut password: Dynamic<String> = "hunter2".into();

// Read
assert_eq!(password.expose_secret(), "hunter2");

// Write
password.expose_secret_mut().push('!');
assert_eq!(password.expose_secret(), "hunter2!");
```

**Use Case**: Passwords, tokens, variable binary data. Heap-allocated, zeroized on drop (with `zeroize`).

## 2. Fixed-Size Byte Arrays (Keys, Nonces)

### Semantic Aliases (Recommended)
```rust
use secure_gate::{fixed_alias, ExposeSecret};

fixed_alias!(pub Aes256Key, 32);
fixed_alias!(pub(crate) InternalNonce, 24);

let key: Aes256Key = [0u8; 32].into();
assert_eq!(key.expose_secret().len(), 32);
```

**Use Case**: Type-safe keys/nonces—prevents mixing sizes.

### TryFrom Slice (Fallible Construction)
```rust
use secure_gate::{Fixed, FromSliceError};

let slice = [0u8; 16];
let nonce: Result<Fixed<[u8; 16]>, FromSliceError> = Fixed::try_from(&slice[..]);
assert!(nonce.is_ok());
```

**Use Case**: Safe construction from untrusted slices.

## 3. Heap Strings & Vectors

### Dynamic String/Vector
```rust
use secure_gate::Dynamic;

let mut token: Dynamic<String> = "api_token".into();
token.expose_secret_mut().push_str("_v2");

let mut payload: Dynamic<Vec<u8>> = vec![1u8; 64].into();
payload.expose_secret_mut().push(0xFF);
```

**Use Case**: API tokens, encrypted payloads, variable secrets.

## 4. Opt-In Safe Cloning (Cloneable Types)

### Pre-Baked Cloneables (Requires `zeroize`)
```rust
#[cfg(feature = "zeroize")]
use secure_gate::{CloneableString, CloneableVec, CloneableArray, ExposeSecret};

#[cfg(feature = "zeroize")]
{
    let pw: CloneableString = "secret".into();
    let pw_clone = pw.clone();  // Safe deep clone + zeroize on drop

    let key: CloneableArray<32> = [0u8; 32].into();
    let key_clone = key.clone();

    let data: CloneableVec = vec![0u8; 128].into();
    let data_clone = data.clone();
}
```

**Use Case**: Secrets needing duplication (e.g., fork safety, caching) without leak risk.

### Safe Construction (Minimize Stack Exposure)
```rust
#[cfg(feature = "zeroize")]
use secure_gate::CloneableString;

#[cfg(feature = "zeroize")]
let pw = CloneableString::try_init_with(|| Ok("from_file_or_input".to_string()));
```

**Use Case**: Reading from untrusted sources (files/user input).

## 5. Cryptographic Randomness (FixedRandom & DynamicRandom)

### RNG-Only Types (Requires `rand`)
```rust
#[cfg(feature = "rand")]
use secure_gate::{FixedRandom, DynamicRandom, ExposeSecret};

#[cfg(feature = "rand")]
{
    let key: FixedRandom<32> = FixedRandom::generate();  // Fresh AES-256 key
    let nonce: FixedRandom<24> = FixedRandom::generate();

    let seed: DynamicRandom = DynamicRandom::generate(64);
    assert_eq!(seed.len(), 64);
}
```

**Use Case**: Keys, nonces, seeds—guaranteed fresh from OS RNG.

### Direct Generation on Core Types
```rust
#[cfg(feature = "rand")]
use secure_gate::Fixed;

#[cfg(feature = "rand")]
let key: Fixed<[u8; 32]> = Fixed::generate_random();
```

**Use Case**: Convenience without separate random type.

## 6. Validated Encodings (Hex, Base64, Bech32)

### Encoding from Secrets (Requires encoding features)
```rust
#[cfg(feature = "encoding-hex")]
use secure_gate::{SecureEncoding, ExposeSecret, encoding::hex::HexString};

#[cfg(feature = "encoding-hex")]
{
    let key: Fixed<[u8; 32]> = Fixed::generate_random();
    let hex = key.expose_secret().to_hex();  // Explicit exposure required
    let hex_str = hex.expose_secret();       // Valid lowercase hex
}
```

**Use Case**: Export keys for configs/APIs (human-readable).

### Validation on Input
```rust
#[cfg(feature = "encoding-base64")]
use secure_gate::encoding::base64::Base64String;

#[cfg(feature = "encoding-base64")]
let validated = Base64String::new("SGVsbG8=".to_string()).expect("valid base64");
```

**Use Case**: Accept encoded input safely (rejects invalid + zeroizes if `zeroize`).

## 7. Serde: Loading Secrets (Deserialize)

### Config Loading (Requires `serde-deserialize` or `serde`)
```rust
#[cfg(feature = "serde")]
use secure_gate::{Dynamic, Fixed};
#[cfg(feature = "serde")]
use serde::Deserialize;

#[cfg(feature = "serde")]
#[derive(Deserialize)]
struct Config {
    api_key: Fixed<[u8; 32]>,
    password: Dynamic<String>,
}

#[cfg(feature = "serde")]
let config: Config = serde_json::from_str(r#"{
    "api_key": [1,2,3,...,32],
    "password": "secret"
}"#).unwrap();
```

**Use Case**: Load secrets from JSON/TOML configs—direct into secure wrappers.

### Encoding Input
```rust
#[cfg(all(feature = "serde", feature = "encoding-hex"))]
use secure_gate::encoding::hex::HexString;

#[cfg(all(feature = "serde", feature = "encoding-hex"))]
let hex_key: HexString = serde_json::from_str(r#""deadbeef""#).unwrap();  // Validates
```

**Use Case**: Accept encoded secrets in configs.

## 8. Serde: Exporting Secrets (Serialize with Marker)

### Opt-In Export (Requires `serde-serialize` or `serde`)
```rust
#[cfg(feature = "serde-serialize")]
use secure_gate::{Fixed, SerializableSecret};

#[cfg(feature = "serde-serialize")]
{
    // Explicitly allow export
    impl SerializableSecret for [u8; 32] {}

    let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
    let json = serde_json::to_string(&key).unwrap();  // → array of bytes
}
```

**Use Case**: Controlled export (e.g., generate key → save to config).

### Export Encoded/Random
```rust
#[cfg(all(feature = "serde-serialize", feature = "encoding-hex"))]
use secure_gate::encoding::hex::HexString;

#[cfg(all(feature = "serde-serialize", feature = "encoding-hex"))]
impl SerializableSecret for String {}  // Allow string encodings

#[cfg(all(feature = "serde-serialize", feature = "encoding-hex"))]
let hex = HexString::new("deadbeef".to_string()).unwrap();
let json = serde_json::to_string(&hex).unwrap();  // → "deadbeef"
```

**Use Case**: Export readable keys/tokens.

## 9. Polymorphic Traits (ExposeSecret, SecureRandom)

### Generic Function Across Wrappers
```rust
use secure_gate::{ExposeSecret, Fixed, Dynamic};

fn secret_len<S: ExposeSecret>(secret: &S) -> usize {
    secret.len()  // Metadata without exposure
}

let fixed: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
let dynamic: Dynamic<String> = "test".into();

assert_eq!(secret_len(&fixed), 32);
assert_eq!(secret_len(&dynamic), 4);
```

**Use Case**: Generic crypto utils without type explosion.

### Random Polymorphism (Requires `rand`)
```rust
#[cfg(feature = "rand")]
use secure_gate::{SecureRandom, FixedRandom};

#[cfg(feature = "rand")]
fn use_random<R: SecureRandom>(rand: &R) {
    let bytes = rand.expose_secret();
    // Use fresh random bytes...
}

#[cfg(feature = "rand")]
let key = FixedRandom::<32>::generate();
use_random(&key);
```

**Use Case**: Generic key derivation from any random source.

## 10. Advanced: Custom Types & Macros

### Custom Cloneable Type
```rust
#[cfg(feature = "zeroize")]
use secure_gate::CloneSafe;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "zeroize")]
#[derive(Clone, Zeroize)]
struct CustomKey([u8; 64]);

#[cfg(feature = "zeroize")]
impl CloneSafe for CustomKey {}

#[cfg(feature = "zeroize")]
let key = CustomKey([0u8; 64]);
let clone = key.clone();  // Safe
```

**Use Case**: Domain-specific secrets with cloning.

### All Macros Overview
```rust
fixed_alias!(pub Aes256Key, 32);
dynamic_alias!(pub Password, String);
#[cfg(feature = "rand")]
fixed_alias_random!(pub Nonce, 24);
#[cfg(feature = "zeroize")]
// exportable_alias! coming soon for serde-serialize opt-in
```

**Use Case**: Semantic, type-safe secrets throughout codebase.