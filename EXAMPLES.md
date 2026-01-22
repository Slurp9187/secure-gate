# secure-gate Examples

This document contains copy-paste-ready, real-world examples for `secure-gate`.

All examples assume the latest version with `"full"` features enabled for completeness:

```toml
secure-gate = { version = "0.7.0-rc.10", features = ["full"] }
```

Adjust features as needed (e.g., minimal builds use `default-features = false`).

**Important notes**:
- Always audit `.expose_secret()` and `.expose_secret_mut()` calls — these are the only access points.
- For production: keep the default `secure` feature (`zeroize` + `ct-eq`) enabled.
- All examples compile and run with the current crate design.

## Table of Contents

1. [Basic Construction & Access](#1-basic-construction--access)
2. [Fixed-Size Secrets (Stack)](#2-fixed-size-secrets-stack)
3. [Dynamic Secrets (Heap)](#3-dynamic-secrets-heap)
4. [Cryptographic Randomness (`rand` feature)](#4-cryptographic-randomness-rand-feature)
5. [Encoding & Decoding (`encoding-*` features)](#5-encoding--decoding-encoding--features)
6. [Opt-In Safe Cloning (`cloneable` feature)](#6-opt-in-safe-cloning-cloneable-feature)
7. [Opt-In Serialization (`serde-serialize` feature)](#7-opt-in-serialization-serde-serialize-feature)
8. [Serde: Loading Secrets (`serde-deserialize`)](#8-serde-loading-secrets-serde-deserialize)
9. [Polymorphic Traits (`ExposeSecret`, `ConstantTimeEq`, `HashEq`)](#9-polymorphic-traits-exposesecret-constanttimeeq-hasheq)
10. [Hash-Based Equality (`hash-eq` feature)](#10-hash-based-equality-hash-eq-feature)
11. [All Macros Overview](#11-all-macros-overview)

## 1. Basic Construction & Access

### Fixed (Stack) – Immutable
```rust
use secure_gate::*;
extern crate alloc;

let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);

let bytes = key.expose_secret();
assert_eq!(bytes.len(), 32);
```

### Fixed (Stack) – Mutable
```rust
use secure_gate::*;
extern crate alloc;

let mut nonce: Fixed<[u8; 12]> = Fixed::new([0u8; 12]);

nonce.expose_secret_mut()[0] = 0xFF;
assert_eq!(nonce.expose_secret()[0], 0xFF);
```

### Dynamic (Heap) – Immutable
```rust
use secure_gate::*;
extern crate alloc;

let password: Dynamic<String> = "hunter2".into();

assert_eq!(password.expose_secret(), "hunter2");
```

### Dynamic (Heap) – Mutable
```rust
use secure_gate::*;
extern crate alloc;

let mut token: Dynamic<String> = "api_token".into();

token.expose_secret_mut().push_str("_v2");
assert_eq!(token.expose_secret(), "api_token_v2");
```

## 2. Fixed-Size Secrets (Stack)

### From Array / Slice (panic on length mismatch)
```rust
use secure_gate::*;
extern crate alloc;

let arr = [0u8; 16];
let nonce: Fixed<[u8; 16]> = arr.into();           // ok
let slice = [0u8; 16];
let nonce2: Fixed<[u8; 16]> = slice[..].into();    // ok
// let wrong: Fixed<[u8; 16]> = [0u8; 15].into();  // compile error or panic
```

### Semantic Aliases (recommended)
```rust
use secure_gate::*;
extern crate alloc;

fixed_alias!(Aes256Key, 32);
fixed_alias!(ApiKey, 32, "API key for external service");

let key: Aes256Key = [0u8; 32].into();
let api_key: ApiKey = [0u8; 32].into();
```

### Generic Fixed Buffer
```rust
use secure_gate::*;
extern crate alloc;

fixed_generic_alias!(SecureBuffer, "Generic fixed-size secure buffer");

let buffer = SecureBuffer::<64>::new([0u8; 64]);
```

## 3. Dynamic Secrets (Heap)

### Semantic Aliases (recommended)
```rust
use secure_gate::*;
extern crate alloc;

dynamic_alias!(Password, String);
dynamic_alias!(Token, Vec<u8>, "OAuth access token");

let pw: Password = "hunter2".into();
let token: Token = vec![0u8; 32].into();
```

### Generic Dynamic Wrapper
```rust
use secure_gate::*;
extern crate alloc;

dynamic_generic_alias!(Secure, "Generic secure heap wrapper");

let bytes = Secure::<Vec<u8>>::new(vec![1, 2, 3]);
let text  = Secure::<String>::new("secret".to_string());
```

## 4. Cryptographic Randomness (`rand` feature)

### Fixed-Size Random
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::*;
    extern crate alloc;

    let key: Fixed<[u8; 32]> = Fixed::from_random();
    assert_eq!(key.len(), 32);
}
```

### Dynamic Random Bytes
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::*;
    extern crate alloc;

    let random: Dynamic<Vec<u8>> = Dynamic::from_random(64);
    assert_eq!(random.len(), 64);
}
```

## 5. Encoding & Decoding (`encoding-*` features)

### Outbound Encoding (via `SecureEncoding` trait)
```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::*;
    extern crate alloc;

    let secret: Fixed<[u8; 16]> = [0xAB; 16].into();
    let hex = secret.expose_secret().to_hex();         // "abababab..."
}
```

```rust
#[cfg(feature = "encoding-base64")]
{
    use secure_gate::*;
    extern crate alloc;

    let bytes = b"Hello".as_slice();
    let b64 = bytes.to_base64url(); // "SGVsbG8"
}
```

### Bech32 Encoding (Fallible)
```rust
#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::*;
    extern crate alloc;

    let bytes = b"Hello world".as_slice();

    // Infallible (panics on error)
    let bech32 = bytes.to_bech32("test"); // "test1w0psnj"

    // Fallible (returns Result)
    let result = bytes.try_to_bech32("test");
    assert!(result.is_ok());
    let bech32_str = result.unwrap();

    // Error handling for invalid HRP
    let invalid_hrp = bytes.try_to_bech32("Invalid_HRP");
    assert!(invalid_hrp.is_err());
    // invalid_hrp.err() => Some(Bech32Error::InvalidHrp)
}
```

### Inbound Decoding (via Serde – auto-detects encoding from strings)
```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
{
    use secure_gate::*;
    use serde_json;
    extern crate alloc;

    // Auto-detects hex
    let valid_hex = r#""deadbeef""#;
    let result: Dynamic<Vec<u8>> = serde_json::from_str(valid_hex).unwrap();
    assert_eq!(result.expose_secret().len(), 4);
}
```

```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
{
    use secure_gate::*;
    use serde_json;
    extern crate alloc;

    // Auto-detects base64
    let valid_b64 = r#""SGVsbG8""#; // "Hello"
    let result: Dynamic<Vec<u8>> = serde_json::from_str(valid_b64).unwrap();
    assert_eq!(result.expose_secret(), b"Hello");
}
```

```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-bech32"))]
{
    use secure_gate::*;
    use serde_json;
    extern crate alloc;

    // Auto-detects bech32 (requires valid HRP)
    let valid_bech32 = r#""bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4""#;
    let result: Dynamic<Vec<u8>> = serde_json::from_str(valid_bech32).unwrap();
}
```

### Safe Decoding (via Serde – no panics on invalid format)
```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
{
    use secure_gate::*;
    use serde_json;
    extern crate alloc;

    let valid_hex = r#""deadbeef""#;
    let result: Result<Dynamic<Vec<u8>>, _> = serde_json::from_str(valid_hex);
    assert!(result.is_ok());

    let invalid = r#""!!!!""#; // Invalid encoding
    let result: Result<Dynamic<Vec<u8>>, _> = serde_json::from_str(invalid);
    assert!(result.is_err());
}
```

## 6. Opt-In Safe Cloning (`cloneable` feature)

### Cloneable Fixed Key
```rust
#[cfg(feature = "cloneable")]
{
    use secure_gate::*;
    extern crate alloc;

    cloneable_fixed_alias!(CloneableKey, 32);

    let key1 = CloneableKey::from([42u8; 32]);
    let key2 = key1.clone(); // safe deep clone
}
```

### Cloneable Dynamic Password
```rust
#[cfg(feature = "cloneable")]
{
    use secure_gate::*;
    extern crate alloc;

    cloneable_dynamic_alias!(CloneablePassword, String);

    let pw1 = CloneablePassword::from("hunter2".to_string());
    let pw2 = pw1.clone(); // safe deep clone
}
```

## 7. Opt-In Serialization (`serde-serialize` feature)

### Serializable Fixed Key
```rust
#[cfg(feature = "serde-serialize")]
{
    use secure_gate::*;
    use serde_json;
    extern crate alloc;


    serializable_fixed_alias!(ExportableKey, 32);

    let key = ExportableKey::from([0u8; 32]);
    let json = serde_json::to_string(&key).unwrap();
}
```

### Serializable Dynamic Token
```rust
#[cfg(feature = "serde-serialize")]
{
    use secure_gate::*;
    use serde_json;
    extern crate alloc;

    serializable_dynamic_alias!(ExportableToken, Vec<u8>);

    let token = ExportableToken::from(vec![1,2,3]);
    let json = serde_json::to_string(&token).unwrap();
}
```

## 8. Serde: Loading Secrets (`serde-deserialize`)

### Loading Config with Secrets
```rust
#[cfg(feature = "serde-deserialize")]
{
    use secure_gate::*;
    use serde::{Deserialize};
    use serde_json;
    extern crate alloc;

    #[derive(Deserialize)]
    struct Config {
        key: Fixed<[u8; 32]>,
        password: Dynamic<String>,
    }

    let json = r#"{
        "key": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
        "password": "hunter2"
    }"#;

    let config: Config = serde_json::from_str(json).unwrap();
}
```

## 9. Polymorphic Traits

### Generic Length Function
```rust
use secure_gate::*;
use secure_gate::{ExposeSecret};
extern crate alloc;

fn secret_len<S: ExposeSecret>(secret: &S) -> usize {
    secret.len()
}

let fixed: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
let dynamic: Dynamic<String> = "secret".into();

assert_eq!(secret_len(&fixed), 32);
assert_eq!(secret_len(&dynamic), 6);
```

### Generic Equality Check
```rust
#[cfg(feature = "ct-eq")]
{
    use secure_gate::*;
    use secure_gate::{ConstantTimeEq};
    extern crate alloc;

    fn secrets_equal<S: ConstantTimeEq>(a: &S, b: &S) -> bool {
        a.ct_eq(b)
    }

    let fixed_a: Fixed<[u8; 32]> = Fixed::new([1u8; 32]);
    let fixed_b: Fixed<[u8; 32]> = Fixed::new([1u8; 32]);
    let dynamic_a: Dynamic<Vec<u8>> = vec![2u8; 32].into();
    let dynamic_b: Dynamic<Vec<u8>> = vec![2u8; 32].into();

    assert!(secrets_equal(&fixed_a, &fixed_b));
    assert!(secrets_equal(&dynamic_a, &dynamic_b));
}
```

### Generic Hash Equality Check
```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::*;
    use secure_gate::{HashEq};
    extern crate alloc;

    fn secrets_hash_equal<S: HashEq>(a: &S, b: &S) -> bool {
        a.hash_eq(b)
    }

    let fixed_a: Fixed<[u8; 32]> = Fixed::new([1u8; 32]);
    let fixed_b: Fixed<[u8; 32]> = Fixed::new([1u8; 32]);
    let dynamic_a: Dynamic<Vec<u8>> = vec![2u8; 32].into();
    let dynamic_b: Dynamic<Vec<u8>> = vec![2u8; 32].into();

    assert!(secrets_hash_equal(&fixed_a, &fixed_b));
    assert!(secrets_hash_equal(&dynamic_a, &dynamic_b));
}
```

## 10. Hash-Based Equality (`hash-eq` feature)

### Probabilistic Constant-Time Equality
```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::*;
    extern crate alloc;

    let a: Fixed<[u8; 32]> = [0u8; 32].into();
    let b: Fixed<[u8; 32]> = [1u8; 32].into();

    assert!(a.hash_eq(&a));
    assert!(!a.hash_eq(&b));
}
```

### Large Secret Equality (Performance Boost)
```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::*;
    extern crate alloc;

    let large_a: Dynamic<Vec<u8>> = vec![42u8; 10000].into();
    let large_b: Dynamic<Vec<u8>> = vec![42u8; 10000].into();

    // Fast BLAKE3-based comparison
    assert!(large_a.hash_eq(&large_b));
}
```

## 11. All Macros Overview

```rust
use secure_gate::*;
extern crate alloc;

// Basic fixed
fixed_alias!(Key32, 32);

// Generic fixed
fixed_generic_alias!(Buffer);

```
// Basic dynamic
dynamic_alias!(SecretString, String);

// Generic dynamic
dynamic_generic_alias!(Secure);

// Cloneable fixed
#[cfg(feature = "cloneable")]
cloneable_fixed_alias!(CloneKey, 32);

// Cloneable dynamic
#[cfg(feature = "cloneable")]
cloneable_dynamic_alias!(ClonePw, String);

// Serializable fixed
#[cfg(feature = "serde-serialize")]
serializable_fixed_alias!(ExportKey, 32);

// Serializable dynamic
#[cfg(feature = "serde-serialize")]
serializable_dynamic_alias!(ExportToken, Vec<u8>);
```
```

All examples compile with `"full"` features. Adjust feature set as needed.
