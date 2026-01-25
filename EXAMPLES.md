# secure-gate Examples

Real-world, copy-paste-ready examples for `secure-gate`.

All examples assume the **recommended secure defaults**:
```toml
[dependencies]
secure-gate = { version = "0.7.0-rc.10", features = ["secure"] } # zeroize + ct-eq
```
For maximum functionality (including `hash-eq`, encodings, serde, etc.), use:
```toml
secure-gate = { version = "0.7.0-rc.10", features = ["full"] }
```

**Important notes**
- Always audit `.expose_secret()` / `.with_secret()` calls — these are the only access points.
- Prefer scoped `with_secret()` / `with_secret_mut()` over long-lived direct exposure.
- Use `hash_eq_opt(…, None)` for most equality checks.
- All examples include `extern crate alloc;` for doctest compatibility (real code usually omits it).

## Table of Contents

1. [Basic Construction & Access](#1-basic-construction--access)
2. [Semantic Aliases with Macros](#2-semantic-aliases-with-macros)
3. [Random Generation](#3-random-generation)
4. [Equality Comparison](#4-equality-comparison)
5. [Encoding & Decoding](#5-encoding--decoding)
6. [Serde (Deserialize & Serialize)](#6-serde-deserialize--serialize)
7. [Opt-In Cloning](#7-opt-in-cloning)
8. [Polymorphic / Generic Code](#8-polymorphic--generic-code)
9. [Construction Patterns (Infallible & Fallible)](#9-construction-patterns-infallible--fallible)

## 1. Basic Construction & Access

### Dynamic (heap-allocated, variable size)

```rust
use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};
extern crate alloc;

let mut pw: Dynamic<String> = "hunter2".into();
let data: Dynamic<Vec<u8>> = vec![1, 2, 3, 4].into();

// Scoped (recommended)
pw.with_secret(|s| println!("length: {}", s.len()));

// Direct (auditable)
assert_eq!(pw.expose_secret(), "hunter2");

// Mutable
pw.with_secret_mut(|s| s.push('!'));
pw.expose_secret_mut().clear();
```

### Fixed (stack-allocated, fixed size)

```rust
use secure_gate::{Fixed, ExposeSecret, ExposeSecretMut};

let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);

// Scoped access (recommended)
let len = key.with_secret(|bytes| bytes.len());
assert_eq!(len, 32);

// Direct access (auditable escape hatch)
assert_eq!(key.expose_secret()[0], 0);

// Mutable
let mut nonce: Fixed<[u8; 12]> = Fixed::new([0u8; 12]);
nonce.with_secret_mut(|bytes| bytes[0] = 0xFF);
nonce.expose_secret_mut()[1] = 0xAA;
```

## 2. Semantic Aliases with Macros

```rust
use secure_gate::{dynamic_alias, fixed_alias};

dynamic_alias!(pub Password, String);      // Dynamic<String>
let pw: Password = "secret123".into();

dynamic_alias!(pub AuthToken, Vec<u8>);    // Dynamic<Vec<u8>>
let token: AuthToken = vec![0u8; 64].into();

fixed_alias!(pub Aes256Key, 32);           // Fixed<[u8; 32]>
let key: Aes256Key = [42u8; 32].into();
```

With custom docs:

```rust
use secure_gate::{dynamic_alias, fixed_alias};

dynamic_alias!(pub RefreshToken, String, "OAuth refresh token");
fixed_alias!(pub ApiKey, 32, "32-byte API key");
```

Generic aliases:

```rust
use secure_gate::{dynamic_generic_alias, fixed_generic_alias};

dynamic_generic_alias!(Secret);
let text: Secret<String> = "hidden".into();

fixed_generic_alias!(SecureBuffer);
let buf: SecureBuffer<64> = [0u8; 64].into();
```

## 3. Random Generation

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{Dynamic, Fixed};
    extern crate alloc;

    // Dynamic (variable size)
    let token: Dynamic<Vec<u8>> = Dynamic::from_random(64);

    // Fixed (fixed size)
    let key: Fixed<[u8; 32]> = Fixed::from_random();

    // Panics on RNG failure — use in trusted environments
}
```

## 4. Equality Comparison

**Recommended: `hash_eq_opt`** — automatically uses `ct_eq` for small inputs, `hash_eq` for large.

```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::{Dynamic, Fixed, HashEq};
    extern crate alloc;

    // Dynamic (large example)
    let sig_a: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();
    let sig_b: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();
    let sig_c: Dynamic<Vec<u8>> = vec![0xBB; 2048].into();

    // Fixed (small example)
    let small_a: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);
    let small_b: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);
    let small_c: Fixed<[u8; 16]> = Fixed::new([2u8; 16]);

    // Recommended: smart path selection
    assert!(sig_a.hash_eq_opt(&sig_b, None));
    assert!(small_a.hash_eq_opt(&small_b, None));

    assert!(!sig_a.hash_eq_opt(&sig_c, None));
    assert!(!small_a.hash_eq_opt(&small_c, None));

    // Force ct_eq on large
    assert!(sig_a.hash_eq_opt(&sig_b, Some(4096)));

    // Force hash_eq on small
    assert!(small_a.hash_eq_opt(&small_b, Some(0)));
}
```

Plain `hash_eq` (uniform probabilistic behavior):

```rust
#[cfg(feature = "hash-eq")]
{
    use secure_gate::{Dynamic, Fixed, HashEq};
    extern crate alloc;

    // Dynamic (large example)
    let sig_a: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();
    let sig_b: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();
    let sig_c: Dynamic<Vec<u8>> = vec![0xBB; 2048].into();

    // Fixed (small example)
    let small_a: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);
    let small_b: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);
    let small_c: Fixed<[u8; 16]> = Fixed::new([2u8; 16]);

    assert!(sig_a.hash_eq(&sig_b));
    assert!(small_a.hash_eq(&small_b));
    assert!(!sig_a.hash_eq(&sig_c));
    assert!(!small_a.hash_eq(&small_c));
}
```

**Timing-safe direct comparison** (`ct-eq`):

```rust
#[cfg(feature = "ct-eq")]
{
    use secure_gate::{ConstantTimeEq, Dynamic, Fixed};
    extern crate alloc;

    // Dynamic (large example)
    let sig_a: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();
    let sig_b: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();

    // Fixed (small example)
    let small_a: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);
    let small_b: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);

    assert!(sig_a.ct_eq(&sig_b));
    assert!(small_a.ct_eq(&small_b));
}
```

## 5. Encoding & Decoding

Per-format symmetric traits for orthogonal encoding/decoding (e.g., `ToHex` / `FromHexStr`).

### Hex Encoding/Decoding

```rust
#[cfg(feature = "encoding-hex")]
{
    use secure_gate::{FromHexStr, ToHex};
    let bytes = [0xDE, 0xAD, 0xBE, 0xEF];

    // Encoding
    let hex = bytes.to_hex();        // "deadbeef"
    let upper = bytes.to_hex_upper(); // "DEADBEEF"

    // Decoding
    let decoded: Vec<u8> = "deadbeef".try_from_hex().unwrap();
    assert_eq!(decoded, bytes);
}
```

### Base64url Encoding/Decoding

```rust
#[cfg(feature = "encoding-base64")]
{
    use secure_gate::{FromBase64UrlStr, ToBase64Url};
    let data = b"Hello World";

    // Encoding
    let b64 = data.to_base64url(); // "SGVsbG8gV29ybGQ"

    // Decoding
    let decoded: Vec<u8> = "SGVsbG8gV29ybGQ".try_from_base64url().unwrap();
    assert_eq!(decoded, data);
}
```

### Bech32/BIP-173 & Bech32m/BIP-350 Encoding/Decoding

```rust
#[cfg(feature = "encoding-bech32")]
{
    use secure_gate::{FromBech32Str, FromBech32mStr, ToBech32, ToBech32m};
    let data = b"test data";

    // Bech32 encoding/decoding
    let bech32 = data.to_bech32("test");           // infallible
    let maybe = data.try_to_bech32("test", None);  // fallible with validation
    let (hrp, decoded) = "test1vejq2p".try_from_bech32().unwrap();

    // Bech32m encoding/decoding (distinct from Bech32)
    let bech32m = data.to_bech32m("test");
    let (hrp_m, decoded_m) = "test1vw3q3p".try_from_bech32m().unwrap();
}
```

### Serde Auto-Decoding (hex/base64url/bech32/bech32m)

```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
{
    use secure_gate::{Dynamic, ExposeSecret};
    use serde_json;
    extern crate alloc;

    // Auto-decodes based on format
    let key: Dynamic<Vec<u8>> = serde_json::from_str(r#""deadbeef""#).unwrap();
    assert_eq!(key.expose_secret(), &[0xDE, 0xAD, 0xBE, 0xEF]);
}
```

### Umbrella Traits (aggregates all enabled formats)

```rust
#[cfg(all(feature = "encoding-hex", feature = "encoding-bech32"))]
{
    use secure_gate::{SecureEncoding, ToHex, ToBech32};  // umbrella includes individual traits
    let bytes = [0xDE, 0xAD, 0xBE, 0xEF];

    // Works via umbrella (same as individual)
    let hex = bytes.to_hex();
    let bech32 = bytes.to_bech32("key");
}
```

## 6. Serde (Deserialize & Serialize)

Deserialize (auto-detects encoding):

```rust
#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
{
    use secure_gate::Dynamic;
    use serde_json;
    extern crate alloc;

    let json = r#""2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a""#;
    let key: Dynamic<Vec<u8>> = serde_json::from_str(json).unwrap();
}
```

Serialize (opt-in):

```rust
#[cfg(feature = "serde-serialize")]
{
    use secure_gate::{Dynamic, SerializableType};
    use serde::Serialize;
    extern crate alloc;

    #[derive(Serialize)]
    struct MyData { secret: Vec<u8> }
    impl SerializableType for MyData {}

    let data = MyData { secret: vec![1, 2, 3] };
    let wrapped: Dynamic<MyData> = data.into();
    let json = serde_json::to_string(&wrapped).unwrap();
}
```

## 7. Opt-In Cloning

```rust
#[cfg(feature = "cloneable")]
{
    use secure_gate::{CloneableType, Dynamic};
    extern crate alloc;

    #[derive(Clone)]
    struct MyKey(Vec<u8>);
    impl CloneableType for MyKey {}

    let key: Dynamic<MyKey> = MyKey(vec![1, 2, 3]).into();
    let copy = key.clone(); // Deep clone allowed
}
```

## 8. Polymorphic / Generic Code

```rust
#[cfg(all(feature = "ct-eq", feature = "hash-eq"))]
{
    use secure_gate::{ExposeSecret, ConstantTimeEq, HashEq};
   
    fn get_len<S: ExposeSecret>(secret: &S) -> usize {
        secret.len()
    }
   
    fn safe_eq<S: ConstantTimeEq>(a: &S, b: &S) -> bool {
        a.ct_eq(b)
    }
   
    fn fast_eq<S: HashEq>(a: &S, b: &S) -> bool {
        a.hash_eq_opt(b, None)  // recommended
    }
}
```

## 9. Construction Patterns (Infallible & Fallible)

```rust
use secure_gate::{Dynamic, Fixed};
extern crate alloc;

// Dynamic (always infallible — copies)
let dyn_vec: Dynamic<Vec<u8>> = vec![5, 6, 7].into();
let dyn_str: Dynamic<String> = "hello".into();
let dyn_slice: Dynamic<Vec<u8>> = [8u8, 9, 10].as_slice().into();

// Fixed (infallible from exact array)
let fixed: Fixed<[u8; 4]> = [1, 2, 3, 4].into();

// Fixed (fallible from slice)
let slice = [8u8, 9, 10, 11];
let ok: Result<Fixed<[u8; 4]>, _> = slice.try_into();
assert!(ok.is_ok());

let short = [12u8, 13];
let err: Result<Fixed<[u8; 4]>, _> = short.as_slice().try_into();
assert!(err.is_err());
```

---

All examples are tested with `"full"` features and should compile cleanly.

Adjust feature flags as needed for minimal builds.
