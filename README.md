# secure-gate

A zero-overhead, `no_std`-compatible secret wrapper with automatic zeroization.

## 0.3.4 – New in this release (2025-11-18)

**The #1 ergonomics complaint is fixed!**

```rust
let pw: SecurePassword = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2"); // ← single call, returns &str

let mut builder = SecurePasswordBuilder::from("base");
builder.expose_secret_mut().push_str("pepper");
let pw: SecurePassword = builder.into_password();
```

No more `pw.expose().expose_secret()` double call!

## Key Features Summary

`secure-gate` is designed for seamless, safe secret handling with **zero runtime overhead** when features are disabled.

- **Auto-Gating**: Switches between `SecretBox<T>` + zeroization (default `zeroize` feature) and plain `Box<T>` fallback — no code changes required.
- **No-Std Native**: Full `no_std` + `alloc` support.
- **Safe & Ergonomic**: All public API in 100% safe Rust; `secure!` macro; convenient aliases (`SecurePassword`, `SecurePasswordBuilder`, `SecureKey32`, etc.).
- **Redacted & Zeroized**: Automatic `Debug` redaction; best-effort zeroization on drop/mutation via `zeroize`.
- **Serde-Ready**: Opt-in serialization (explicitly exposes the secret in serialized form).
- **Fuzz-Hardened**: 5 libFuzzer targets running nightly.
- **Zero-Alloc Fixed Secrets**: Stack-only types for keys/nonces (default via `stack` feature).

## Installation

```toml
[dependencies]
secure-gate = "0.3.4"
```

## Quick Start

```rust
use secure_gate::{SecurePassword, SecurePasswordBuilder, secure};

let pw: SecurePassword = "hunter2".into();          // immutable, zeroized on drop
assert_eq!(pw.expose_secret(), "hunter2");           // ← direct &str access!

let mut builder = SecurePasswordBuilder::from("base");
builder.expose_secret_mut().push_str("pepper");
builder.finish_mut();                               // shrink excess capacity
let pw: SecurePassword = builder.into_password();    // or .build()

let key = secure!([u8; 32], rand::random());         // generic or fixed-size
```

### Zero-Allocation Fixed-Size Secrets (default)

```rust
use secure_gate::{SecureKey32, key32};

static AES_KEY: SecureKey32 = key32([0x42; 32]);     // const-eligible, stack-only
let nonce = secure!([u8; 12], [0; 12]);
assert_eq!(&*nonce, &[0u8; 12]);
```

## Features

| Feature        | Effect                                                          |
|----------------|-----------------------------------------------------------------|
| `zeroize`      | Enables zeroization + `SecretBox<T>` (default)                  |
| `stack`        | Zero-allocation fixed-size keys/nonces (default)                |
| `serde`        | Serialize / Deserialize support                                |
| `unsafe-wipe`  | Fast, allocation-free wipe for `Secure<String>` (opt-in)       |
| `full`         | All of the above                                                |

## Zeroization Guarantees

Same strong guarantees as the `zeroize` crate:
- Overwrites secret memory on drop/mutation
- Works on all stable targets
- Stack aliases use `Zeroizing<[u8; N]>` — zero heap, deterministic
- `finish_mut()` reduces excess capacity (best-effort)

See the crate docs for full details and limitations.

## License

MIT OR Apache-2.0