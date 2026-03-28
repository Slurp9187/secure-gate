# secure-gate-compat

[![Crates.io](https://img.shields.io/crates/v/secure-gate-compat.svg)](https://crates.io/crates/secure-gate-compat)
[![Docs.rs](https://docs.rs/secure-gate-compat/badge.svg)](https://docs.rs/secure-gate-compat)
[![MSRV: 1.85](https://img.shields.io/badge/msrv-1.85-blue)](https://github.com/Slurp9187/secure-gate/blob/main/Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

Compatibility shims for migrating from the [`secrecy`](https://crates.io/crates/secrecy) crate (v0.8.0 and v0.10.1).

**This crate is intended for migration only.** New code should use the native types from the [`secure-gate`](https://crates.io/crates/secure-gate) crate directly.

## Installation

```toml
[dependencies]
secure-gate-compat = { version = "0.9", features = ["secrecy-compat"] }
```

## Quick Migration Example

```rust
// secrecy v0.10.x
use secure_gate_compat::compat::v10::{SecretBox, SecretString};
use secure_gate_compat::compat::ExposeSecret;

// secrecy v0.8.x
use secure_gate_compat::compat::v08::{Secret, SecretString, DebugSecret};
use secure_gate_compat::compat::{CloneableSecret, ExposeSecret};
```

Your existing code should compile with only import changes. See the full guide for type mappings, `From` conversions, and incremental replacement steps.

## Features

- `secrecy-compat` — enables the `compat::v08` and `compat::v10` modules + bridge traits
- `dual-compat-test` — enables side-by-side parity tests against the real `secrecy` crate (dev only)

## Further Reading

- **[MIGRATING_FROM_SECRECY.md](https://github.com/Slurp9187/secure-gate/blob/main/secure-gate-compat/MIGRATING_FROM_SECRECY.md)** — complete migration guide, parity test suite, and security notes
- **[SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/secure-gate-compat/SECURITY.md)** — security considerations for the compatibility layer (including migration-specific risks)
- [Core `secure-gate` documentation](https://docs.rs/secure-gate) — preferred API for new code

The compat layer is a thin, zero-overhead shim. Once migration is complete, remove the `secrecy-compat` feature and the `secure-gate-compat` dependency.
