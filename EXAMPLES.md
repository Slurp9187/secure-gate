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
4. [Opt-In Safe Cloning (`cloneable` feature)](#opt-in-safe-cloning)
5. [Cryptographic Randomness (`rand` feature)](#cryptographic-randomness)
6. [Encoding (`encoding-*` features)](#encoding)
7. [Serde: Loading Secrets (`serde-deserialize`)](#serde-loading-secrets)
8. [Serde: Exporting Secrets (`serde-serialize` with marker)](#serde-exporting-secrets)
9. [Polymorphic Traits (ExposeSecret, ConstantTimeEq)](#polymorphic-traits)
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
extern crate alloc;

use secure_gate::{Dynamic, ExposeSecret};

let password: Dynamic<alloc::string::String> = "hunter2".into(); // Heap-allocated

// Immutable access
assert_eq!(password.expose_secret(), "hunter2");
```
**Use Case**: Read-only variable-length secrets (e.g., loaded tokens).

### Dynamic (Heap) Secret (Mutable Access)
```rust
extern crate alloc;

use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};

let mut password: Dynamic<alloc::string::String> = "hunter2".into();

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

### From Slice (Panic on Length Mismatch)
```rust
use secure_gate::Fixed;

let slice = [0u8; 16];
let nonce: Fixed<[u8; 16]> = slice[..].into(); // Panics if length != 16
```
**Use Case**: Fail-fast exact-length from slices.

## 3. Dynamic (Heap) Strings & Vectors
### Dynamic (Heap) String (Immutable)
```rust
extern crate alloc;

use secure_gate::{Dynamic, ExposeSecret};

let token: Dynamic<alloc::string::String> = "api_token".into();

// Immutable access
assert_eq!(token.expose_secret(), "api_token");
```
**Use Case**: Read-only strings (e.g., tokens).

### Dynamic (Heap) String (Mutable)
```rust
extern crate alloc;

use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};

let mut token: Dynamic<alloc::string::String> = "api_token".into();

// Mutable access
token.expose_secret_mut().push_str("_v2");
assert_eq!(token.expose_secret(), "api_token_v2");
```
**Use Case**: Building/modifying strings.

### Dynamic (Heap) Vector (Immutable)
```rust
extern crate alloc;

use secure_gate::{Dynamic, ExposeSecret};

let payload: Dynamic<alloc::vec::Vec<u8>> = alloc::vec![1u8; 64].into();

// Immutable access
assert_eq!(payload.expose_secret().len(), 64);
```
**Use Case**: Read-only binary data.

### Dynamic (Heap) Vector (Mutable)
```rust
extern crate alloc;

use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};

let mut payload: Dynamic<alloc::vec::Vec<u8>> = alloc::vec![1u8; 64].into();

// Mutable access
payload.expose_secret_mut().push(0xFF);
assert_eq!(payload.expose_secret()[64], 0xFF);
```
**Use Case**: Appending to payloads.

## 4. Opt-In Safe Cloning (`cloneable` feature)
Cloning is opt-in via `CloneableType` marker and convenience macros.

### Cloneable Fixed Array
```rust
#[cfg(feature = "cloneable")]
use secure_gate::{cloneable_fixed_alias, ExposeSecret};

#[cfg(feature = "cloneable")]
{
    extern crate alloc;
    cloneable_fixed_alias!(pub CloneableKey, 32);

    let key: CloneableKey = [0u8; 32].into();

    let key2 = key.clone(); // Safe deep clone
}
```

Custom:
```rust
#[cfg(feature = "cloneable")]
use secure_gate::CloneableType;

#[cfg(feature = "cloneable")]
{
    use zeroize::Zeroize;

    #[derive(Clone, Zeroize)]
    struct MyKey([u8; 32]);

    impl CloneableType for MyKey {}

    let key = MyKey([42u8; 32]);
    let copy = key.clone();
}
```

## 5. Cryptographic Randomness (`rand` feature)
Random generation is direct on core types (guaranteed system entropy via OsRng).

### Fixed (Stack) Random
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{Fixed, ExposeSecret};

    let key: Fixed<[u8; 32]> = Fixed::from_random();

    assert_eq!(key.len(), 32);
}
```

### Dynamic (Heap) Random
```rust
#[cfg(feature = "rand")]
extern crate alloc;

#[cfg(feature = "rand")]
{
    use secure_gate::{Dynamic, ExposeSecret};

    let random_bytes: Dynamic<alloc::vec::Vec<u8>> = Dynamic::from_random(64);

    assert_eq!(random_bytes.len(), 64);
}
```

## 6. Encoding (`encoding-*` features)
Outbound encoding uses the `SecureEncoding` trait on `expose_secret()` (returns `String`).

Inbound decoding via direct constructors (panic on invalid).

### Outbound Encoding (Trait)
```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::{Fixed, SecureEncoding, ExposeSecret};

    let secret: Fixed<[u8; 16]> = [0u8; 16].into();

    let hex = secret.expose_secret().to_hex(); // String: "000000..."
    let hex_upper = secret.expose_secret().to_hex_upper(); // "000000..."
}

#[cfg(feature = "encoding-base64")]
{
    use secure_gate::SecureEncoding;

    let bytes = b"Hello".as_slice();
    let base64 = bytes.to_base64url(); // "SGVsbG8"
}

#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::SecureEncoding;

    let bytes = b"hello".as_slice();
    let bech32 = bytes.to_bech32("bc"); // panics on error
    let bech32m = bytes.to_bech32m("tb"); // panics on error
}
```

### Inbound Decoding (Constructors)
```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::Dynamic;

    let key = Dynamic::<Vec<u8>>::from_hex("deadbeefdeadbeefdeadbeefdeadbeef");
}

#[cfg(feature = "encoding-base64")]
extern crate alloc;

#[cfg(feature = "encoding-base64")]
{
    use secure_gate::Dynamic;

    let data = Dynamic::<alloc::vec::Vec<u8>>::from_base64("SGVsbG8");
}

#[cfg(feature = "encoding-bech32")]

#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::Dynamic;

    let data = Dynamic::<alloc::vec::Vec<u8>>::from_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc");
}
```

## 7. Serde: Loading Secrets (`serde-deserialize`)
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

## 8. Serde: Exporting Secrets (`serde-serialize` with marker)
Raw serialization is opt-in via `SerializableType` marker and convenience macros (risky — audit carefully).

### Fixed Exportable
```rust
#[cfg(feature = "serde-serialize")]
use secure_gate::serializable_fixed_alias;

#[cfg(feature = "serde-serialize")]
{
    extern crate alloc;
    serializable_fixed_alias!(pub ExportableKey, 32);

    let key: ExportableKey = [0u8; 32].into();
}
```

Custom:
```rust
#[cfg(feature = "serde-serialize")]
use secure_gate::SerializableType;

#[cfg(feature = "serde-serialize")]
{
    use serde::Serialize;

    #[derive(Serialize)]
    struct RawKey([u8; 32]);

    impl SerializableType for RawKey {}

    let key = RawKey([42u8; 32]);
}
```

## 9. Polymorphic Traits (ExposeSecret, ConstantTimeEq)
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

### Constant-Time Equality (`ct-eq`)
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
