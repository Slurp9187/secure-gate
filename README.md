# secure-gate

**Experimental crate — under active development**

Zero-overhead, `no_std`-compatible secret wrappers with configurable zeroization.

**Current status**: The crate is in an experimental phase. The public API is stabilizing, but breaking changes are still possible (especially in the 0.5.0 release). Use in production with caution.

## v0.4.2 – 2025-11-20

This release fixes a long-standing regression and brings the crate to a stable, fully-tested state.

### Fixed
- #27: Restored `.expose_secret()` and `.expose_secret_mut()` on `SecurePassword` and `SecurePasswordBuilder`
- `SecurePasswordBuilder` now supports full mutation and `.build()`
- `SecureStackPassword` is now truly zero-heap using `zeroize::Zeroizing<[u8; 128]>`
- All accessors work correctly under `--no-default-features`

### Added
- `expose_secret_bytes()` and `expose_secret_bytes_mut()` (gated behind `unsafe-wipe`)
- Comprehensive regression test suite (`tests/password_tests.rs`) with 8+ guards

### Improved
- Zero warnings under `cargo clippy --all-features -- -D warnings`
- All tests pass on every feature combination

## Features

| Feature        | Effect                                                                 |
|----------------|------------------------------------------------------------------------|
| `zeroize`      | Enables zeroization via `secrecy` + `zeroize` (on by default)          |
| `stack`        | Zero-allocation fixed-size secrets using `Zeroizing<T>` (on by default)|
| `unsafe-wipe`  | Enables full allocation wiping (including spare capacity)              |
| `serde`        | Serialization support                                                  |
| `full`         | All features above                                                     |

- `no_std` + `alloc` compatible
- Redacted `Debug` and `Serialize` output
- Test coverage includes timing safety and slack wiping

## Installation

```toml
[dependencies]
secure-gate = "0.4.2"
```

Enable full wiping:
```toml
secure-gate = { version = "0.4.2", features = ["unsafe-wipe"] }
```

## Quick Start

```rust
use secure_gate::{SecureGate, SecurePassword, secure};

// Immutable password
let pw: SecurePassword = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");

// Mutable builder
let mut builder = SecurePasswordBuilder::from("base");
builder.expose_secret_mut().push_str("pepper");
let pw: SecurePassword = builder.build();

// Fixed-size keys (stack-allocated when `stack` enabled)
let key = secure!([u8; 32], rand::random::<[u8; 32]>());
let key = secure_gate::key32([0x42; 32]);
```

### Accessors

```rust
let s: &str = gate.expose_secret();           // password types
let s: &mut String = gate.expose_secret_mut(); // builder only
let raw: &T = gate.expose();                  // generic access
```

## Migration from 0.3.x

All existing code continues to compile via the `deprecated` module.  
The underlying type has changed from `Secure<T>` / `HeapSecure<T>` to `SecureGate<T>`.

```rust
// Old
let s = HeapSecure::new("data".to_string());

// New
let s = SecureGate::new("data".to_string());
type SG<T> = SecureGate<T>;
let s = SG::new("data".to_string());
```

## Planned for 0.5.0

The current API has overlapping accessor names (`.expose()` vs `.expose_secret()` etc.).  
A future 0.5.0 release will simplify this significantly — likely removing the `expose_secret*` methods in favor of a cleaner, more consistent design.

## License

Dual-licensed under MIT OR Apache-2.0, at your option.