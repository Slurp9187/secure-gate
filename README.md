# secure-gate

Zero-overhead, `no_std`-compatible secret wrappers with **configurable zeroization**.

## v0.4.1 – 2025-11-20

### New in 0.4.1 – Configurable Zeroization Modes

```rust
use secure_gate::{SecureGate, ZeroizeMode};

let pw = SecureGate::new("hunter2".to_string());                    // Safe mode (default)
let pw_full = SecureGate::new_full_wipe("hunter2".to_string());     // Full wipe (incl. slack)
let pw_pass = SecureGate::new_passthrough("hunter2".to_string());   // No extra wiping

let pw_custom = SecureGate::with_mode("hunter2".to_string(), ZeroizeMode::Full);
```

- **`Safe`** (default) – wipes only used bytes (no `unsafe`)
- **`Full`** – wipes **entire allocation** including spare capacity (`unsafe-wipe` feature)
- **`Passthrough`** – relies only on inner type’s `Zeroize` impl

Perfect for defense-in-depth, compliance, or performance trade-offs.

## Features

| Feature        | Effect                                                                 |
|----------------|------------------------------------------------------------------------|
| `zeroize`      | Enables zeroization via `secrecy` + `zeroize` (on by default)          |
| `stack`        | Zero-allocation fixed-size secrets using `Zeroizing<T>` (on by default)|
| `unsafe-wipe`  | Enables `Full` zeroization mode (wipes spare capacity)                 |
| `serde`        | Serialization support                                                  |
| `full`         | All features above                                                     |

- `no_std` + `alloc` compatible
- Zero runtime overhead when `zeroize` is disabled
- Redacted `Debug` output
- Full test coverage including timing safety

## Installation

```toml
[dependencies]
secure-gate = "0.4.1"
```

Enable full wiping:
```toml
secure-gate = { version = "0.4.1", features = ["unsafe-wipe"] }
```

## Quick Start

```rust
use secure_gate::{SecureGate, SecurePassword, secure};

// Immutable password (recommended)
let pw: SecurePassword = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");

// Mutable builder
let mut builder = SecurePasswordBuilder::from("base");
builder.expose_secret_mut().push_str("pepper");
let pw: SecurePassword = builder.build();

// Fixed-size keys (stack-allocated when `stack` enabled)
let key = secure!([u8; 32], rand::random::<[u8; 32]>());  // Zeroizing<[u8; 32]>
let key = secure_gate::key32([0x42; 32]);                // same thing
```

### Accessors

```rust
let secret: &str = gate.expose_secret();
let secret: &mut String = gate.expose_secret_mut();
```

Use `.expose_secret()` — it's the canonical, zero-cost way.

## Why secure-gate?

- **Zero overhead** when zeroization is disabled
- **True stack allocation** for fixed-size keys
- **Configurable wiping strategy** — from safe to paranoid
- **No breaking changes** from 0.3.x → 0.4.x (deprecated aliases preserved)
- **Extensively tested** including slack wiping, timing variance, and concurrency

## Migration from 0.3.x

All your existing code continues to compile:
```rust
use secure_gate::SecurePassword;  // still works
use secure_gate::Secure;          // deprecated but available
```

Only the underlying generic type changed:
```rust
// Old
let s = HeapSecure::new("data".to_string());

// New (recommended)
let s = SecureGate::new("data".to_string());
// or
type SG<T> = SecureGate<T>;
let s = SG::new("data".to_string());
```

## License

Dual-licensed under MIT OR Apache-2.0, at your option.