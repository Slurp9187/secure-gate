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
9. [Polymorphic Traits (`ExposeSecret`, `ConstantTimeEq`)](#9-polymorphic-traits-exposesecret-constanttimeeq)
10. [All Macros Overview](#10-all-macros-overview)

## 1. Basic Construction & Access

### Fixed (Stack) – Immutable
```rust
use secure_gate::{Fixed, ExposeSecret};

let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);

let bytes = key.expose_secret();
assert_eq!(bytes.len(), 32);
```

### Fixed (Stack) – Mutable
```rust
use secure_gate::{Fixed, ExposeSecretMut};

let mut nonce: Fixed<[u8; 12]> = Fixed::new([0u8; 12]);

nonce.expose_secret_mut()[0] = 0xFF;
assert_eq!(nonce.expose_secret()[0], 0xFF);
```

### Dynamic (Heap) – Immutable
```rust
use secure_gate::{Dynamic, ExposeSecret};

let password: Dynamic<String> = "hunter2".into();

assert_eq!(password.expose_secret(), "hunter2");
```

### Dynamic (Heap) – Mutable
```rust
use secure_gate::{Dynamic, ExposeSecretMut};

let mut token: Dynamic<String> = "api_token".into();

token.expose_secret_mut().push_str("_v2");
assert_eq!(token.expose_secret(), "api_token_v2");
```

## 2. Fixed-Size Secrets (Stack)

### From Array / Slice (panic on length mismatch)
```rust
use secure_gate::Fixed;

let arr = [0u8; 16];
let nonce: Fixed<[u8; 16]> = arr.into();           // ok
let slice = [0u8; 16];
let nonce2: Fixed<[u8; 16]> = slice[..].into();    // ok
// let wrong: Fixed<[u8; 16]> = [0u8; 15].into();  // compile error or panic
```

### Semantic Aliases (recommended)
```rust
use secure_gate::fixed_alias;

fixed_alias!(pub Aes256Key, 32);
fixed_alias!(pub ApiKey, 32, "API key for external service");

let key: Aes256Key = [0u8; 32].into();
let api_key: ApiKey = [0u8; 32].into();
```

### Generic Fixed Buffer
```rust
use secure_gate::fixed_generic_alias;

fixed_generic_alias!(pub SecureBuffer, "Generic fixed-size secure buffer");

let buffer = SecureBuffer::<64>::new([0u8; 64]);
```

## 3. Dynamic Secrets (Heap)

### Semantic Aliases (recommended)
```rust
use secure_gate::dynamic_alias;

dynamic_alias!(pub Password, String);
dynamic_alias!(pub Token, Vec<u8>, "OAuth access token");

let pw: Password = "hunter2".into();
let token: Token = vec![0u8; 32].into();
```

### Generic Dynamic Wrapper
```rust
use secure_gate::dynamic_generic_alias;

dynamic_generic_alias!(pub Secure, "Generic secure heap wrapper");

let bytes = Secure::<Vec<u8>>::new(vec![1, 2, 3]);
let text  = Secure::<String>::new("secret".to_string());
```

## 4. Cryptographic Randomness (`rand` feature)

### Fixed-Size Random
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::Fixed;

    let key: Fixed<[u8; 32]> = Fixed::from_random();
    assert_eq!(key.len(), 32);
}
```

### Dynamic Random Bytes
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::Dynamic;

    let random: Dynamic<Vec<u8>> = Dynamic::from_random(64);
    assert_eq!(random.len(), 64);
}
```

## 5. Encoding & Decoding (`encoding-*` features)

### Outbound Encoding (via `SecureEncoding` trait)
```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::{Fixed, SecureEncoding, ExposeSecret};

    let secret: Fixed<[u8; 16]> = [0xAB; 16].into();
    let hex = secret.expose_secret().to_hex();         // "abababab..."
}
```

```rust
#[cfg(feature = "encoding-base64")]
{
    use secure_gate::SecureEncoding;

    let bytes = b"Hello".as_slice();
    let b64 = bytes.to_base64url(); // "SGVsbG8"
}
```

### Inbound Decoding (via constructors – panic on invalid)
```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::Dynamic;

    let key = Dynamic::<Vec<u8>>::from_hex("deadbeefdeadbeef");
}
```

```rust
#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::Dynamic;

    let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let bytes = Dynamic::<Vec<u8>>::from_bech32(addr, "bc");
}
```

### Safe Decoding (Result-returning)
```rust
#[cfg(feature = "encoding-base64")]
{
    use secure_gate::Dynamic;

    let result = Dynamic::<Vec<u8>>::try_from_base64("SGVsbG8");
    assert!(result.is_ok());
}
```

## 6. Opt-In Safe Cloning (`cloneable` feature)

### Cloneable Fixed Key
```rust
#[cfg(feature = "cloneable")]
use secure_gate::cloneable_fixed_alias;

#[cfg(feature = "cloneable")]
{
    cloneable_fixed_alias!(pub CloneableKey, 32);

    let key1 = CloneableKey::from([42u8; 32]);
    let key2 = key1.clone(); // safe deep clone
}
```

### Cloneable Dynamic Password
```rust
#[cfg(feature = "cloneable")]
use secure_gate::cloneable_dynamic_alias;

#[cfg(feature = "cloneable")]
{
    cloneable_dynamic_alias!(pub CloneablePassword, String);

    let pw1 = CloneablePassword::from("hunter2".to_string());
    let pw2 = pw1.clone(); // safe deep clone
}
```

## 7. Opt-In Serialization (`serde-serialize` feature)

### Serializable Fixed Key
```rust
#[cfg(feature = "serde-serialize")]
use secure_gate::serializable_fixed_alias;

#[cfg(feature = "serde-serialize")]
{
    serializable_fixed_alias!(pub ExportableKey, 32);

    let key = ExportableKey::from([0u8; 32]);
    let json = serde_json::to_string(&key).unwrap();
}
```

### Serializable Dynamic Token
```rust
#[cfg(feature = "serde-serialize")]
use secure_gate::serializable_dynamic_alias;

#[cfg(feature = "serde-serialize")]
{
    serializable_dynamic_alias!(pub ExportableToken, Vec<u8>);

    let token = ExportableToken::from(vec![1,2,3]);
    let json = serde_json::to_string(&token).unwrap();
}
```

## 8. Serde: Loading Secrets (`serde-deserialize`)

### Loading Config with Secrets
```rust
#[cfg(feature = "serde-deserialize")]
{
    use secure_gate::{Fixed, Dynamic};
    use serde::Deserialize;

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
use secure_gate::{ExposeSecret, Fixed, Dynamic};

fn secret_len<S: ExposeSecret>(secret: &S) -> usize {
    secret.len()
}

let fixed: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
let dynamic: Dynamic<String> = "secret".into();

assert_eq!(secret_len(&fixed), 32);
assert_eq!(secret_len(&dynamic), 6);
```

## 10. All Macros Overview

```rust
use secure_gate::{
    fixed_alias, fixed_generic_alias,
    dynamic_alias, dynamic_generic_alias,
    cloneable_fixed_alias, cloneable_dynamic_alias,
    serializable_fixed_alias, serializable_dynamic_alias
};

// Basic fixed
fixed_alias!(pub Key32, 32);

// Generic fixed
fixed_generic_alias!(pub Buffer);

// Basic dynamic
dynamic_alias!(pub SecretString, String);

// Generic dynamic
dynamic_generic_alias!(pub Secure<T>);

// Cloneable fixed
cloneable_fixed_alias!(pub CloneKey, 32);

// Cloneable dynamic
cloneable_dynamic_alias!(pub ClonePw, String);

// Serializable fixed
serializable_fixed_alias!(pub ExportKey, 32);

// Serializable dynamic
serializable_dynamic_alias!(pub ExportToken, Vec<u8>);
```

All examples compile with `"full"` features. Adjust feature set as needed.