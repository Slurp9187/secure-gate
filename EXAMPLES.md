# secure-gate Examples

This document contains copy-paste-ready, real-world examples for `secure-gate` v0.7.0.

All examples assume `"full"` features for completeness:
```toml
secure-gate = { version = "0.7.0-rc.10", features = ["full"] }
```
Adjust features for minimal builds (e.g., `default-features = false`).

**Notes**:
- Audit all `.expose_secret()`/`.with_secret()` calls—these are explicit access points.
- Keep `secure` feature (`zeroize` + `ct-eq`) enabled in production.
- Examples include `extern crate alloc;` for doctest compatibility (real-world code may not need it).

## Table of Contents
1. [Basic Construction & Access](#1-basic-construction--access)
2. [Dynamic Secrets (Heap)](#2-dynamic-secrets-heap)
3. [Fixed-Size Secrets (Stack)](#3-fixed-size-secrets-stack)
4. [Cryptographic Randomness (`rand`)](#4-cryptographic-randomness-rand)
5. [Encoding & Decoding (`encoding-*`)](#5-encoding--decoding-encoding-)
6. [Opt-In Cloning (`cloneable`)](#6-opt-in-cloning-cloneable)
7. [Opt-In Serialization (`serde-serialize`)](#7-opt-in-serialization-serde-serialize)
8. [Loading Secrets (`serde-deserialize`)](#8-loading-secrets-serde-deserialize)
9. [Polymorphic Traits](#9-polymorphic-traits)
10. [Hash-Based Equality (`hash-eq`)](#10-hash-based-equality-hash-eq)
11. [Construction & Fallibility](#11-construction--fallibility)
12. [Macros Overview](#12-macros-overview)

## 1. Basic Construction & Access



### Fixed (Stack) – Immutable
```rust
use secure_gate::*;
extern crate alloc;

let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);

// Scoped access (preferred)
let len = key.with_secret(|bytes| bytes.len());
assert_eq!(len, 32);

// Direct access (auditable)
let bytes = key.expose_secret();
assert_eq!(bytes[0], 0);
```

### Fixed (Stack) – Mutable
```rust
use secure_gate::*;
extern crate alloc;

let mut nonce: Fixed<[u8; 12]> = Fixed::new([0u8; 12]);

// Scoped mutation
nonce.with_secret_mut(|bytes| bytes[0] = 0xFF);

// Direct mutation
nonce.expose_secret_mut()[1] = 0xAA;

assert_eq!(nonce.expose_secret()[0], 0xFF);
assert_eq!(nonce.expose_secret()[1], 0xAA);
```

## 2. Dynamic Secrets (Heap)

### From Array/Slice (Infallible)
```rust
use secure_gate::*;
extern crate alloc;

let arr = [0u8; 16];
let fixed: Fixed<[u8; 16]> = arr.into();  // Exact match
```

### From Slice (Fallible)
```rust
use secure_gate::*;
extern crate alloc;

let slice: &[u8] = &[0u8; 16];
let result: Result<Fixed<[u8; 16]>, _> = slice.try_into();
assert!(result.is_ok());

let short: &[u8] = &[0u8; 8];
let fail: Result<Fixed<[u8; 16]>, _> = short.try_into();
assert!(fail.is_err());
```

### Semantic Aliases
```rust
use secure_gate::*;
extern crate alloc;

fixed_alias!(pub Aes256Key, 32);
fixed_alias!(pub ApiKey, 32, "API key for service");

let key: Aes256Key = [42u8; 32].into();
let api_key: ApiKey = [0u8; 32].into();
```

### Generic Fixed Alias
```rust
use secure_gate::*;
extern crate alloc;

fixed_generic_alias!(SecureBuffer);

let buffer: SecureBuffer<64> = [0u8; 64].into();
```

## 3. Fixed-Size Secrets (Stack)

### From Owned Values
```rust
use secure_gate::*;
extern crate alloc;

let str_dyn: Dynamic<String> = "password".to_string().into();
let vec_dyn: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
```

### From Slices (Copies)
```rust
use secure_gate::*;
extern crate alloc;

let slice = [1u8, 2, 3, 4].as_slice();
let dyn_vec: Dynamic<Vec<u8>> = slice.into();  // Copies
assert_eq!(dyn_vec.expose_secret(), &[1, 2, 3, 4]);
```

### Semantic Aliases
```rust
use secure_gate::*;
extern crate alloc;

dynamic_alias!(Password, String);
dynamic_alias!(Token, Vec<u8>, "OAuth token");

let pw: Password = "secret".into();
let token: Token = vec![0u8; 32].into();
```

### Generic Dynamic Alias
```rust
use secure_gate::*;
extern crate alloc;

dynamic_generic_alias!(Secret);

let data: Secret<Vec<u8>> = vec![42; 64].into();
let text: Secret<String> = "hidden".into();
```

## 4. Cryptographic Randomness (`rand`)

### Fixed Random
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::*;
    extern crate alloc;

    let key: Fixed<[u8; 32]> = Fixed::from_random();
    assert_eq!(key.len(), 32);
    // Panics on RNG failure
}
```

### Dynamic Random
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::*;
    extern crate alloc;

    let data: Dynamic<Vec<u8>> = Dynamic::from_random(128);
    assert_eq!(data.len(), 128);
}
```

## 5. Encoding & Decoding (`encoding-*`)

### Hex Encoding
```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::*;
    extern crate alloc;

    let secret = [0xDE, 0xAD, 0xBE, 0xEF];
    let hex = secret.to_hex();  // "deadbeef"
    let upper = secret.to_hex_upper();  // "DEADBEEF"
}
```

### Base64 Encoding
```rust
#[cfg(feature = "encoding-base64")]
{
    use secure_gate::*;
    extern crate alloc;

    let data = b"Hello World";
    let b64 = data.to_base64url();  // "SGVsbG8gV29ybGQ"
}
```

### Bech32 Encoding
```rust
#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::*;
    extern crate alloc;

    let data = b"test data";

    // Infallible (panics on error)
    let bech32 = data.to_bech32("test");  // e.g., "test1..."

    // Fallible
    match data.try_to_bech32("test", None) {
        Ok(encoded) => println!("Encoded: {}", encoded),
        Err(e) => eprintln!("Error: {:?}", e),
    }
}
```

### Serde Auto-Decoding
```rust
// #[cfg(all(feature = "serde-deserialize", any(feature = "encoding-hex", feature = "encoding-base64", feature = "encoding-bech32")))]
// {
//     use secure_gate::*;
//     use serde_json;
//     extern crate alloc;

//     // Hex: "deadbeef"
//     let hex: Dynamic<Vec<u8>> = serde_json::from_str(r#""deadbeef""#).expect("Failed to decode hex string");

//     // Base64: "SGVsbG8"
//     let b64: Dynamic<Vec<u8>> = serde_json::from_str(r#""SGVsbG8""#).unwrap();

//     // Bech32 (valid HRP required)
//     #[cfg(feature = "encoding-bech32")]
//     let bech32: Dynamic<Vec<u8>> = serde_json::from_str(r#""test1..."#).unwrap();
// }
```

## 6. Opt-In Cloning (`cloneable`)

### Implement CloneableType
```rust
#[cfg(feature = "cloneable")]
{
    use secure_gate::CloneableType;

    #[derive(Clone)]
    struct MySecret([u8; 32]);

    impl CloneableType for MySecret {}

    let original = MySecret([42; 32]);
    let cloned = original.clone();  // Now allowed on Fixed/Dynamic
}
```

### Wrapping for Cloning
```rust
#[cfg(feature = "cloneable")]
{
    use secure_gate::*;
    extern crate alloc;

    #[derive(Clone)]
    struct MyKey(Vec<u8>);

    impl CloneableType for MyKey {}

    let key: Dynamic<MyKey> = MyKey(vec![1, 2, 3]).into();
    let copy = key.clone();  // Deep clone
}
```

## 7. Opt-In Serialization (`serde-serialize`)

### Implement SerializableType
```rust
#[cfg(feature = "serde-serialize")]
{
    use secure_gate::{SerializableType, Dynamic};
    use serde::Serialize;

    #[derive(Serialize)]
    struct MyData { secret: Vec<u8> }

    impl SerializableType for MyData {}

    let data = MyData { secret: vec![1, 2, 3] };
    let wrapped: Dynamic<MyData> = data.into();
    let json = serde_json::to_string(&wrapped).unwrap();  // Allowed
}
```

## 8. Loading Secrets (`serde-deserialize`)

### Config with Secrets
```rust
#[cfg(feature = "serde-deserialize")]
{
    use secure_gate::*;
    use serde::Deserialize;
    use serde_json;
    extern crate alloc;

    #[derive(Deserialize)]
    struct Config {
        api_key: Fixed<[u8; 32]>,
        password: Dynamic<String>,
    }

    let json = r#"{
        "api_key": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
        "password": "secret123"
    }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert_eq!(config.password.expose_secret(), "secret123");
}
```

## 9. Polymorphic Traits

### Generic Access
```rust
use secure_gate::*;
extern crate alloc;

fn get_len<S: ExposeSecret>(secret: &S) -> usize {
    secret.len()
}

let dynamic: Dynamic<Vec<u8>> = vec![1; 8].into();
let fixed: Fixed<[u8; 16]> = [0; 16].into();

assert_eq!(get_len(&dynamic), 8);
assert_eq!(get_len(&fixed), 16);
```

### Constant-Time Equality
```rust
#[cfg(feature = "ct-eq")]
{
    use secure_gate::*;
    extern crate alloc;

    fn safe_eq<S: ConstantTimeEq>(a: &S, b: &S) -> bool {
        a.ct_eq(b)
    }

    let a: Dynamic<Vec<u8>> = vec![1; 4].into();
    let b: Dynamic<Vec<u8>> = vec![1; 4].into();
    assert!(safe_eq(&a, &b));
}
```

### Hash Equality
```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::*;
    extern crate alloc;

    fn hash_eq<S: HashEq>(a: &S, b: &S) -> bool {
        a.hash_eq(b)
    }

    let large_a: Dynamic<Vec<u8>> = vec![42; 1000].into();
    let large_b: Dynamic<Vec<u8>> = vec![42; 1000].into();
    assert!(hash_eq(&large_a, &large_b));  // Fast
}
```

## 10. Hash-Based Equality (`hash-eq`)

### Basic Usage
```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::*;
    extern crate alloc;

    let a: Fixed<[u8; 32]> = [1; 32].into();
    let b: Fixed<[u8; 32]> = [1; 32].into();
    let c: Fixed<[u8; 32]> = [2; 32].into();

    assert!(a.hash_eq(&b));
    assert!(!a.hash_eq(&c));
}
```

### Performance for Large Data
```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::*;
    extern crate alloc;

    let big_a: Dynamic<Vec<u8>> = vec![0; 10000].into();
    let big_b: Dynamic<Vec<u8>> = vec![0; 10000].into();

    // BLAKE3 hash comparison (fast for large secrets)
    assert!(big_a.hash_eq(&big_b));
}
```

## 11. Construction & Fallibility

### Fixed Construction
```rust
use secure_gate::*;
extern crate alloc;

// Infallible from exact array
let fixed: Fixed<[u8; 4]> = [1, 2, 3, 4].into();

// Fallible from slice
let slice: &[u8] = &[5, 6, 7, 8];
let ok: Result<Fixed<[u8; 4]>, _> = slice.try_into();
assert!(ok.is_ok());

let mismatch: &[u8] = &[9, 10];
let err: Result<Fixed<[u8; 4]>, _> = mismatch.try_into();
assert!(err.is_err());
```

### Dynamic Construction
```rust
use secure_gate::*;
extern crate alloc;

// Always infallible (copies)
let from_vec: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
let from_str: Dynamic<String> = "hello".into();
let from_slice: Dynamic<Vec<u8>> = [4u8, 5, 6].as_slice().into();
```

## 12. Macros Overview

```rust
use secure_gate::*;
extern crate alloc;

// Fixed aliases
fixed_alias!(MyKey, 32);
fixed_alias!(pub ApiKey, 16, "API key");  // Doc version with custom documentation

// Dynamic aliases
dynamic_alias!(Password, String);
dynamic_alias!(pub Token, Vec<u8>, "Auth token");  // Doc version with custom documentation

// Generics
fixed_generic_alias!(Buffer);
dynamic_generic_alias!(Secret);

// Usage
let key: MyKey = [0u8; 32].into();
let api: ApiKey = [1u8; 16].into();
let pw: Password = "pass".into();
let tok: Token = vec![2u8; 8].into();
let buf: Buffer<64> = [1u8; 64].into();
let sec: Secret<String> = "hidden".into();
```

All examples are copy-paste ready for real-world use.

All examples compile with `"full"` features. Adjust feature set as needed.
