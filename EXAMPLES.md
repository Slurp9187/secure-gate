# secure-gate Examples

Real-world, copy-paste-ready examples for `secure-gate`.

All examples assume the **recommended secure defaults** (includes zeroize, ct-eq, and alloc for heap support):
```toml
[dependencies]
secure-gate = { version = "0.7.0-rc.11", features = ["secure"] } # zeroize + alloc
```

For maximum functionality (including `ct-eq-hash`, encodings, serde, etc.), use:
```toml
secure-gate = { version = "0.7.0-rc.11", features = ["full"] }
```

For **no-heap builds**, enable `no-alloc` to restrict to `Fixed<T>` (stack-allocated). `Dynamic<T>` requires alloc (included by default with `secure`):
```toml
secure-gate = { version = "0.7.0-rc.11", features = ["secure", "no-alloc"] } # stack-only with security
```

**Important notes**
- Always audit `.expose_secret()` / `.with_secret()` calls — these are the only access points.
- Prefer scoped `with_secret()` / `with_secret_mut()` over long-lived direct exposure.
- Use `ct_eq_auto(…, None)` for most equality checks.
- All examples include `extern crate alloc;` for doctest compatibility (real code usually omits it); in no-alloc builds, avoid heap types entirely.

**Warning**: Enabling both `alloc` and `no-alloc` features allows `alloc` to take precedence (e.g., with `--all-features` for docs generation or CI). Prefer enabling only one feature for predictable builds.

## Table of Contents

1. [Basic Construction & Access](#1-basic-construction--access)
1.1. [No-Alloc Builds](#11-no-alloc-builds)
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
#[cfg(feature = "alloc")]
{
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
}
```

*Note: `Dynamic<T>` requires the `alloc` feature (included by default with `secure`). In no-alloc builds, use `Fixed<T>` for fixed-size secrets.*

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

## 1.1. No-Alloc Builds

In no-alloc builds (`no-alloc` feature), only `Fixed<T>` is available — `Dynamic<T>` is unavailable as it requires heap allocation.

```rust
#[cfg(feature = "no-alloc")]
{
    use secure_gate::{Fixed, ExposeSecret};
    // Only Fixed<T> available — no heap
    let key: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
    key.with_secret(|bytes| assert_eq!(bytes.len(), 32));
}

#[cfg(all(feature = "rand", feature = "no-alloc"))]
{
    use secure_gate::Fixed;
    // Random Fixed<T> works even in no-alloc (Dynamic::from_random requires alloc)
    let random_key: Fixed<[u8; 32]> = Fixed::from_random();
}
```

## 2. Semantic Aliases with Macros

```rust
#[cfg(feature = "alloc")]
{
use secure_gate::{dynamic_alias, fixed_alias};

dynamic_alias!(pub Password, String);      // Dynamic<String>
let pw: Password = "secret123".into();

dynamic_alias!(pub AuthToken, Vec<u8>);    // Dynamic<Vec<u8>>
let token: AuthToken = vec![0u8; 64].into();
}

use secure_gate::fixed_alias;

fixed_alias!(pub Aes256Key, 32);           // Fixed<[u8; 32]>
let key: Aes256Key = [42u8; 32].into();
```

With custom docs:

```rust
#[cfg(feature = "alloc")]
{
use secure_gate::{dynamic_alias, fixed_alias};

dynamic_alias!(pub RefreshToken, String, "OAuth refresh token");
}

use secure_gate::fixed_alias;

fixed_alias!(pub ApiKey, 32, "32-byte API key");
```

Generic aliases:

```rust
#[cfg(feature = "alloc")]
{
use secure_gate::{dynamic_generic_alias, fixed_generic_alias};

dynamic_generic_alias!(Secret);
let text: Secret<String> = "hidden".into();
}

use secure_gate::fixed_generic_alias;

fixed_generic_alias!(SecureBuffer);
let buf: SecureBuffer<64> = [0u8; 64].into();
```

## 3. Random Generation

```rust
#[cfg(feature = "rand")]
{
    #[cfg(feature = "alloc")]
    use secure_gate::Dynamic;
    use secure_gate::Fixed;
    #[cfg(feature = "alloc")]
    extern crate alloc;

    // Dynamic (variable size)
    #[cfg(feature = "alloc")]
    let token: Dynamic<Vec<u8>> = Dynamic::from_random(64);

    // Fixed (fixed size)
    let key: Fixed<[u8; 32]> = Fixed::from_random();

    // Panics on RNG failure — use in trusted environments
}
```

## 4. Equality Comparison

**Recommended: `ct_eq_auto`** — automatically uses `ct_eq` for ≤32 bytes, `ct_eq_hash` (BLAKE3) for larger inputs.

```rust
#[cfg(feature = "ct-eq-hash")]
{
    #[cfg(feature = "alloc")]
    use secure_gate::Dynamic;
    use secure_gate::{Fixed, ConstantTimeEqExt};
    #[cfg(feature = "alloc")]
    extern crate alloc;

    // Dynamic (large example)
    #[cfg(feature = "alloc")]
    let sig_a: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();
    #[cfg(feature = "alloc")]
    let sig_b: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();
    #[cfg(feature = "alloc")]
    let sig_c: Dynamic<Vec<u8>> = vec![0xBB; 2048].into();

    // Fixed (small example)
    let small_a: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);
    let small_b: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);
    let small_c: Fixed<[u8; 16]> = Fixed::new([2u8; 16]);

    // Recommended: smart path selection
    #[cfg(feature = "alloc")]
    assert!(sig_a.ct_eq_auto(&sig_b, None));
    assert!(small_a.ct_eq_auto(&small_b, None));

    #[cfg(feature = "alloc")]
    assert!(!sig_a.ct_eq_auto(&sig_c, None));
    assert!(!small_a.ct_eq_auto(&small_c, None));

    // Customize threshold for performance tuning on your hardware
    // Example: Force ct_eq path up to 16 bytes (if benchmarks show it's still faster)
    #[cfg(feature = "alloc")]
    assert!(sig_a.ct_eq_auto(&sig_b, Some(16)));

    // Example: Force hash path for all sizes (uniform probabilistic behavior)
    assert!(small_a.ct_eq_auto(&small_b, Some(0)));
}
```

**Performance Tuning**: If your benchmarks indicate `ct_eq` remains more performant beyond 32 bytes (e.g., on specialized hardware or for large caches), set a higher threshold like `Some(64)` or `Some(1024)`. Conversely, use lower values for conservative probabilistic equality. Always profile your target system!

For detailed justification, benchmarks, and tuning guidance, see [CT_EQ_AUTO.md](CT_EQ_AUTO.md).
}

Plain `ct_eq_hash` (uniform probabilistic behavior):

```rust
#[cfg(feature = "ct-eq-hash")]
{
    #[cfg(feature = "alloc")]
    use secure_gate::Dynamic;
    use secure_gate::{Fixed, ConstantTimeEqExt};
    #[cfg(feature = "alloc")]
    extern crate alloc;

    // Dynamic (large example)
    #[cfg(feature = "alloc")]
    let sig_a: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();
    #[cfg(feature = "alloc")]
    let sig_b: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();
    #[cfg(feature = "alloc")]
    let sig_c: Dynamic<Vec<u8>> = vec![0xBB; 2048].into();

    // Fixed (small example)
    let small_a: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);
    let small_b: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);
    let small_c: Fixed<[u8; 16]> = Fixed::new([2u8; 16]);

    #[cfg(feature = "alloc")]
    assert!(sig_a.ct_eq_hash(&sig_b));
    assert!(small_a.ct_eq_hash(&small_b));
    #[cfg(feature = "alloc")]
    assert!(!sig_a.ct_eq_hash(&sig_c));
    assert!(!small_a.ct_eq_hash(&small_c));
}
```

**Timing-safe direct comparison** (`ct-eq`):

```rust
#[cfg(feature = "ct-eq")]
{
    use secure_gate::{ConstantTimeEq, Fixed};
    #[cfg(feature = "alloc")]
    use secure_gate::Dynamic;
    #[cfg(feature = "alloc")]
    extern crate alloc;

    // Dynamic (large example)
    #[cfg(feature = "alloc")]
    let sig_a: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();
    #[cfg(feature = "alloc")]
    let sig_b: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();

    // Fixed (small example)
    let small_a: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);
    let small_b: Fixed<[u8; 16]> = Fixed::new([1u8; 16]);

    #[cfg(feature = "alloc")]
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
    use secure_gate::{ToBech32, ToBech32m};
    let data = b"test data";

    // Preferred: fallible with optional HRP validation
    let bech32  = data.try_to_bech32("test", None).unwrap();
    let bech32m = data.try_to_bech32m("test", None).unwrap();

    // Infallible versions still exist but may panic on invalid input
    let _ = data.to_bech32("test");
    let _ = data.to_bech32m("test");
}
```

### Serde Direct Binary Deserialization

```rust
#[cfg(all(feature = "serde-deserialize", feature = "alloc", feature = "rand"))]
{
    use secure_gate::{Dynamic, ExposeSecret};
    use serde_json;
    extern crate alloc;

    // Round-trip: serialize binary data to JSON array, then deserialize directly
    let original: Dynamic<Vec<u8>> = Dynamic::from_random(4);
    let json = serde_json::to_string(original.expose_secret()).unwrap();
    let decoded: Dynamic<Vec<u8>> = serde_json::from_str(&json).unwrap();
    assert_eq!(original.expose_secret(), decoded.expose_secret());
}
```

### Manual Decoding with Specific Traits

```rust
#[cfg(all(feature = "encoding-hex", feature = "encoding-base64"))]
{
    use secure_gate::{Fixed, FromHexStr, FromBase64UrlStr};

    // Decode specific formats manually
    let hex_bytes = "deadbeef".try_from_hex().unwrap();
    let b64_bytes = "aGVsbG8".try_from_base64url().unwrap();

    // Then wrap in secure types
    let key: Fixed<[u8; 4]> = secure_gate::Fixed::new(hex_bytes.as_slice().try_into().unwrap());
}
```

### Explicit Decoding Constructors on Wrappers

```rust
#[cfg(all(feature = "encoding-hex", feature = "encoding-base64", feature = "alloc"))]
{
    use secure_gate::{Dynamic, Fixed, ExposeSecret};
    extern crate alloc;

    // Direct construction from encoded strings (new in v0.7.0)
    let fixed_key = Fixed::<[u8; 4]>::try_from_hex("deadbeef").unwrap();
    let dynamic_data = Dynamic::<Vec<u8>>::try_from_base64url("aGVsbG8").unwrap();

    assert_eq!(fixed_key.expose_secret(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(dynamic_data.expose_secret(), b"hello");
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
    let bech32 = bytes.try_to_bech32("key", None).unwrap();
}
```

## 6. Serde (Deserialize & Serialize)

Deserialize (direct binary from JSON array):

```rust
#[cfg(all(feature = "serde-deserialize", feature = "alloc"))]
{
    use secure_gate::Dynamic;
    use serde_json;
    extern crate alloc;

    let json = r#"[42,42,42,42]"#;
    let key: Dynamic<Vec<u8>> = serde_json::from_str(json).unwrap();
}
```

Serialize (opt-in, requires `SerializableType` marker):

```rust
#[cfg(all(feature = "serde-serialize", feature = "alloc"))]
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
#[cfg(all(feature = "cloneable", feature = "alloc"))]
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
#[cfg(all(feature = "ct-eq", feature = "ct-eq-hash"))]
{
    use secure_gate::{ExposeSecret, ConstantTimeEq, ConstantTimeEqExt};

    fn get_len<S: ExposeSecret>(secret: &S) -> usize {
        secret.len()
    }

    fn safe_eq<S: ConstantTimeEq>(a: &S, b: &S) -> bool {
        a.ct_eq(b)
    }

    fn fast_eq<S: ConstantTimeEqExt>(a: &S, b: &S) -> bool {
        a.ct_eq_auto(b, None)  // recommended
    }
}
```

## 9. Construction Patterns (Infallible & Fallible)

```rust
#[cfg(feature = "alloc")]
use secure_gate::Dynamic;
use secure_gate::Fixed;
#[cfg(feature = "alloc")]
extern crate alloc;

// Dynamic (always infallible — copies)
#[cfg(feature = "alloc")]
let dyn_vec: Dynamic<Vec<u8>> = vec![5, 6, 7].into();
#[cfg(feature = "alloc")]
let dyn_str: Dynamic<String> = "hello".into();
#[cfg(feature = "alloc")]
let dyn_slice: Dynamic<Vec<u8>> = [8u8, 9, 10].as_slice().into();

// Fixed (infallible from exact array)
let fixed: Fixed<[u8; 4]> = [1, 2, 3, 4].into();

// Fixed (fallible from slice)
let slice = [8u8, 9, 10, 11];
let ok: Result<Fixed<[u8; 4]>, _> = slice.try_into();
assert!(ok.is_ok());
```

---

All examples are tested with `"full"` features (includes alloc) and should compile cleanly.

For no-alloc builds, test with `["secure", "no-alloc"]` and adjust for stack-only usage. Adjust feature flags as needed for minimal builds. Test with Rust 1.70+.
