# secure-gate

Zero-overhead, `no_std`-compatible secret wrappers with optional automatic zeroization.

## 0.4.0 – 2025-11-20

### What changed
- Unified public API under a single generic type: `SecureGate<T>`  
  (replaces the previous `HeapSecure` / `Secure<T>` naming)
- The crate root now re-exports `SecureGate` and the short alias `SG<T>`
- Fixed-size secrets now use `zeroize::Zeroizing` directly when the `stack` feature is enabled (no wrapper overhead)
- All existing type aliases (`SecurePassword`, `SecureKey32`, `SecureNonce24`, constructors, etc.) remain unchanged
- Legacy names (`Secure<T>`, `HeapSecure<T>`, etc.) are preserved via a `deprecated` module so 0.3.x code continues to compile (with deprecation warnings)

No breaking functionality changes — only renaming and internal cleanup.

## Features

- Zero runtime overhead when the `zeroize` feature is disabled (plain `Box<T>` fallback)
- Full zeroization when `zeroize` is enabled (via `secrecy` + `zeroize`)
- Zero-allocation fixed-size secrets via the `stack` feature (uses `Zeroizing` directly)
- `no_std` + `alloc` compatible
- Safe, ergonomic API with convenient aliases
- `secure!` macro for easy construction
- Optional `serde` support
- Redacted `Debug` output

## Installation

```toml
[dependencies]
secure-gate = "0.4.0"
```

## Quick Start

```rust
use secure_gate::{SecureGate, SecurePassword, secure};

let pw: SecurePassword = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");   // single call → &str

let mut builder = SecurePasswordBuilder::from("base");
builder.expose_secret_mut().push_str("pepper");
let pw: SecurePassword = builder.into_password();

let key = secure!([u8; 32], rand::random()); // fixed-size, stack-allocated when `stack` enabled
```

### Fixed-size constructors (available when the `stack` feature is enabled)

```rust
use secure_gate::{key32, nonce24};

let aes_key = key32([0x42; 32]);     // Zeroizing<[u8; 32]>
let nonce   = nonce24([0; 24]);      // Zeroizing<[u8; 24]>
```

## Feature matrix

| Feature        | Effect                                                       |
|----------------|--------------------------------------------------------------|
| `zeroize`      | Enables zeroization + `SecretBox<T>` (on by default)         |
| `stack`        | Zero-allocation fixed-size secrets (on by default)           |
| `serde`        | Serialization support                                        |
| `unsafe-wipe`  | Faster zeroization for `SecureGate<String>` (opt-in)         |
| `full`         | All of the above                                             |

## Zeroization guarantees

Same guarantees as the `zeroize` crate:
- Secrets are overwritten on drop and explicit mutation
- Stack-based fixed-size types are zeroized without heap allocation
- `finish_mut()` reduces excess capacity where possible

See the crate documentation for details and limitations.

## Migration from 0.3.x

All public aliases and functionality remain available.  
Only the internal generic type name changed from `Secure<T>` / `HeapSecure<T>` to `SecureGate<T>`.  
Old names are provided through the `deprecated` module with compiler warnings.

## License

MIT OR Apache-2.0