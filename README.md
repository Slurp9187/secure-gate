# secure-gate

A zero-overhead, `no_std`-compatible secret wrapper with automatic zeroization.

[![Crates.io](https://img.shields.io/crates/v/secure-gate.svg)](https://crates.io/crates/secure-gate)
[![Documentation](https://docs.rs/secure-gate/badge.svg)](https://docs.rs/secure-gate)
[![Fuzzing Status](https://github.com/Slurp9187/secure-gate/actions/workflows/fuzz.yml/badge.svg)](https://github.com/Slurp9187/secure-gate/actions/workflows/fuzz.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

- `no_std` + `alloc` support
- `zeroize` feature enabled by default
- Redacted `Debug` output
- `serde` support (opt-in)
- All public API in safe Rust

## Key Feature: Auto-Gating Between Secure and Standard Modes

A core design choice is automatic gating: with the `zeroize` feature (default), `Secure<T>` uses `SecretBox<T>` for zeroization on drop. When `zeroize` is disabled, it falls back to plain `Box<T>` for minimal overhead in constrained environments (e.g., embedded). This ensures seamless compatibility without code changes — your code works identically across builds.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
secure-gate = "0.1"
```

## Usage

### Basic Wrappers

```rust
use secure_gate::{SecurePassword, Secure};

let password: SecurePassword = "hunter2".into();  // zeroized on drop
let key = Secure::<[u8; 32]>::new(rand::random());  // fixed-size key
let token = Secure::<Vec<u8>>::new(vec![...]);  // dynamic buffer
let secret_str = Secure::<str>::from("hello");  // unsized str
```

### Scoped Mutation (Preferred)

```rust
let mut pw = SecurePassword::from("pass");
{
    let mut inner = pw.expose_mut();
    inner.push_str("word");  // Scoped to avoid long holds
}
pw.finish_mut();  // Shrink capacity + zero excess (if zeroize enabled)
```

### Cloning and Extraction

```rust
let pw1 = SecurePassword::from("original");
let pw2 = pw1.clone();  // Scoped clone + zeroize local (if zeroize enabled)

let extracted: String = pw2.into_inner();  // Extract with wipe of original
```

### FromStr Parsing

```rust
use std::str::FromStr;

let nonce = SecureNonce16::from_str("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();  // Hex parse
let pw = SecurePassword::from_str("passphrase").unwrap();  // Direct string
```

### Serde Round-Trip (Opt-In)

```rust
use serde_json;

let pw = SecurePassword::from("secret");
let json = serde_json::to_string(&pw).unwrap();  // Serializes via inner
let round = serde_json::from_str::<SecurePassword>(&json).unwrap();
assert_eq!(round.expose().as_str(), "secret");
```

### Macro Ergonomics

```rust
use secure_gate::secure;

let key = secure!([u8; 32], [0u8; 32]);  // Array literal
let vec = secure!(Vec<u8>, vec![1, 2, 3]);  // Dynamic vec
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
zeroize = { version = "1.8", optional = true, default-features