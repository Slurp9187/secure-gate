# secure-gate

A zero-overhead, `no_std`-compatible secret wrapper with automatic zeroization.

[![Crates.io](https://img.shields.io/crates/v/secure-gate.svg)](https://crates.io/crates/secure-gate)
[![Documentation](https://docs.rs/secure-gate/badge.svg)](https://docs.rs/secure-gate)
[![Fuzzing Status](https://github.com/YourName/secure-gate/actions/workflows/fuzz.yml/badge.svg)](https://github.com/YourName/secure-gate/actions/workflows/fuzz.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

- `no_std` + `alloc` support
- `zeroize` feature enabled by default
- Redacted `Debug` output
- `serde` support (opt-in)
- All public API in safe Rust

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
secure-gate = "0.1"
```

## Usage

```rust
use secure_gate::{SecurePassword, Secure};

let password: SecurePassword = "hunter2".into();  // zeroized on drop
let key = Secure::<[u8; 32]>::new(rand::random());  // fixed-size key
let token = Secure::<Vec<u8>>::new(vec![...]);  // dynamic buffer

// Scoped mutation (preferred)
password.expose_mut().push_str("!!!");
password.finish_mut();  // shrink + zero excess capacity

// Extraction (use sparingly)
let bytes: Vec<u8> = token.into_inner();  // original zeroized immediately
```

## Fuzzing Configuration

| Target    | Description                                      | Runtime per CI run |
|-----------|--------------------------------------------------|--------------------|
| `expose`  | Memory access + `finish_mut`                     | 60 minutes         |
| `clone`   | `init_with`, `into_inner`, scoped zeroization    | 60 minutes         |
| `serde`   | JSON + bincode deserialization from untrusted input | 60 minutes      |
| `parsing` | `FromStr` parsing                                | 60 minutes         |
| `debug`   | `Debug` redaction verification                   | 60 minutes         |
| `mut`     | Unbounded `expose_mut()` mutation stress         | 60 minutes         |
| `drop`    | Drop and zeroization safety                      | 60 minutes         |

- 7 libFuzzer targets
- 420 CPU minutes per nightly run (7 × 60 min)
- Runs on GitHub Actions (ubuntu-latest, nightly toolchain)
- `-rss_limit_mb=4096`, `-max_total_time=3600`, `-timeout=60`
- Artifacts uploaded on every run
- All targets currently pass with no crashes

## Dependencies

```toml
[dependencies]
secrecy = { version = "0.10.3", optional = true, default-features = false }
zeroize = { version = "1.8", optional = true, default-features = false, features = ["alloc", "zeroize_derive"] }
serde = { version = "1.0", features = ["derive"], optional = true }
```

## Features

| Feature   | Effect                                              |
|-----------|-----------------------------------------------------|
| `zeroize` | Enables `SecretBox<T>` + zeroization on drop (default) |
| `serde`   | Adds `Serialize` / `Deserialize` impls              |

## Auto-Gating Between Secure and Standard Modes

A key feature is automatic gating: with the `zeroize` feature (default), `Secure<T>` uses `SecretBox<T>` for zeroization. When disabled, it falls back to plain `Box<T>` for minimal overhead in constrained environments. This ensures seamless compatibility without code changes.

## Zeroization Guarantees

`Secure<T>` provides **best-effort memory zeroization** on drop/mutation via the `zeroize` crate:

- **What It Does**: Explicitly overwrites secret bytes (up to `.len()` for dynamic types like `Vec`/`String`) using volatile operations that resist compiler optimization.
- **Platform Coverage**: Works on all stable Rust targets (x86, ARM, RISC-V, etc.) via portable intrinsics. No guarantees against hardware leaks (e.g., cache side-channels)—use constant-time primitives alongside.
- **Limitations**: Only affects the wrapped value; doesn't secure against copies, logs, or kernel dumps. For full protection, avoid extraction (`into_inner`) and use scoped `expose_mut()`.
- **Fallback Mode**: Disabled without `zeroize` feature—treat as plain `Box<T>`.

For details, see [zeroize docs](https://docs.rs/zeroize).

## Contribution

Contributions welcome! Please submit PRs with tests/fuzz targets. See [fuzzing docs](fuzz/README.md) for extending fuzz suite.

## License

Licensed under MIT OR Apache-2.0