# secure-gate workspace

[![Docs.rs](https://docs.rs/secure-gate/badge.svg)](https://docs.rs/secure-gate/0.8.0-rc.8/secure_gate/)
[![CI](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml/badge.svg?branch=release%2F0.8)](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml?query=branch%3Arelease%2F0.8)
[![MSRV: 1.70](https://img.shields.io/badge/msrv-1.70-blue)](https://github.com/Slurp9187/secure-gate/blob/release/0.8/Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Secure wrappers for in-memory secrets with **explicit access** and **mandatory zeroization** — a `no_std`-compatible, zero-overhead library with audit-friendly access patterns.

> [!WARNING]
> This crate has **not undergone independent audit**.
> Review the code and [SECURITY.md](secure-gate-core/SECURITY.md) before production use.

## Crates

| Crate                                       | Published as                                                        | Purpose                                                       |
| ------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------- |
| [`secure-gate-core`](secure-gate-core/)     | [`secure-gate`](https://crates.io/crates/secure-gate)               | Core library — `Fixed<T>`, `Dynamic<T>`, encoding, serde, rng |
| [`secure-gate-compat`](secure-gate-compat/) | [`secure-gate-compat`](https://crates.io/crates/secure-gate-compat) | Migration shims for `secrecy` v0.8 and v0.10                  |

## Quick Start

```toml
[dependencies]
secure-gate = "0.8"
```

```rust
use secure_gate::{dynamic_alias, fixed_alias, RevealSecret, RevealSecretMut};

dynamic_alias!(pub Password, String);  // Dynamic<String>
fixed_alias!(pub Aes256Key, 32);       // Fixed<[u8; 32]>

let mut pw: Password = "hunter2".into();
let key: Aes256Key = Aes256Key::new([42u8; 32]);

// Scoped access — the borrow cannot outlive the closure
pw.with_secret(|s| println!("length: {}", s.len()));

// Mutable scoped access
pw.with_secret_mut(|s: &mut String| s.push('!'));

// Direct reference — auditable escape hatch (FFI, third-party APIs)
assert_eq!(pw.expose_secret(), "hunter2!");
```

All types print `[REDACTED]` in `Debug` output and zeroize their memory on drop.

## Security

- **No `Deref`** — secrets cannot be accessed accidentally; all access is via `.with_secret()`, `.expose_secret()`, or `.into_inner()`
- **Mandatory zeroization** — full buffer cleared on drop (including spare heap capacity)
- **No unsafe code** — `#![forbid(unsafe_code)]` enforced unconditionally
- **Timing-safe comparison** — `.ct_eq()` via the `ct-eq` feature (uses `subtle`)
- **Opt-in risk** — cloning and serialization require explicit marker traits (`CloneableSecret`, `SerializableSecret`)
- **Verified** — semantic drop-order tests, physical heap-byte verification via `ProxyAllocator`, AddressSanitizer in CI, Miri on nightly

## Workspace Layout

```
secure-gate-workspace/
├── Cargo.toml              workspace root
├── CHANGELOG.md            workspace-level changelog
├── secure-gate-core/       core library (published as "secure-gate")
│   ├── src/
│   ├── tests/
│   ├── benches/
│   ├── fuzz/
│   ├── README.md
│   ├── SECURITY.md
│   ├── CHANGELOG.md
│   └── ROADMAP.md
└── secure-gate-compat/     secrecy migration shims
    ├── src/
    ├── tests/
    ├── README.md
    ├── SECURITY.md
    └── MIGRATING_FROM_SECRECY.md
```

## Documentation

- [secure-gate API docs](https://docs.rs/secure-gate) — full rustdoc reference
- [secure-gate-compat API docs](https://docs.rs/secure-gate-compat)
- [secure-gate-core/README.md](secure-gate-core/README.md) — core library guide (features, encoding, serde, rng, macros)
- [secure-gate-compat/README.md](secure-gate-compat/README.md) — compat quick-start
- [secure-gate-compat/MIGRATING_FROM_SECRECY.md](secure-gate-compat/MIGRATING_FROM_SECRECY.md) — full migration guide for secrecy v0.8 and v0.10
- [secure-gate-core/SECURITY.md](secure-gate-core/SECURITY.md) — threat model, audit surface, best practices
- [secure-gate-core/CHANGELOG.md](secure-gate-core/CHANGELOG.md) — detailed version history
- [secure-gate-core/ROADMAP.md](secure-gate-core/ROADMAP.md) — planned features and release branches

## CI

The CI pipeline (`release/0.8` branch) runs lint, test, MSRV (1.70), AddressSanitizer heap verification, and libFuzzer/Miri targets. See [`.github/workflows/`](.github/workflows/).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
