# secure-gate

A zero-overhead, `no_std`-compatible secret wrapper with automatic zeroization.

## Key Features Summary

`secure-gate` is designed for seamless, safe secret handling with **zero runtime overhead** when features are disabled. Core highlights:

- **Auto-Gating**: Switches between `SecretBox<T>` + zeroization (default `zeroize` feature) and plain `Box<T>` fallback for minimal builds—no code changes required.
- **No-Std Native**: Full `no_std` + `alloc` support for embedded/embedded systems.
- **Safe & Ergonomic**: All public API in 100% safe Rust; `secure!` macro for quick construction; aliases like `SecurePassword` (immutable default), `SecurePasswordMut` (mutable opt-in), and `SecureKey32`.
- **Redacted & Zeroized**: Automatic `Debug` redaction (`"[REDACTED]"`); best-effort zeroization on drop/mutation via `zeroize`.
- **Serde-Ready**: Opt-in serialization of secrets (explicitly exposes the secret in serialized form, e.g., JSON strings; protect output bytes appropriately).
- **Fuzz-Hardened**: 6 libFuzzer targets running 360 CPU minutes nightly—zero crashes/leaks after thousands of hours.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
secure-gate = "0.2"
```

## Usage

```rust
use secure_gate::{SecurePassword, SecurePasswordMut, Secure};

let password: SecurePassword = "hunter2".into();  // Immutable default, zeroized on drop

let key = Secure::<[u8; 32]>::new(rand::random());  // fixed-size key
let token = Secure::<Vec<u8>>::new(vec![...]);  // dynamic buffer

// Scoped mutation (preferred for mutable cases)
let mut pw_mut: SecurePasswordMut = SecurePasswordMut::new("base".to_string());
pw_mut.expose_mut().expose_secret_mut().push_str("!!!");
pw_mut.finish_mut();  // reduce excess capacity via shrink_to_fit (best-effort; no scrub of freed memory)

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

- 6 libFuzzer targets
- 360 CPU minutes per nightly run (6 × 60 min)
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

## Zeroization Guarantees

`Secure<T>` provides **best-effort memory zeroization** on drop/mutation via the `zeroize` crate:

- **What It Does**: Explicitly overwrites secret bytes (up to `.len()` for dynamic types like `Vec`/`String`) using volatile operations that resist compiler optimization.
- **Platform Coverage**: Works on all stable Rust targets (x86, ARM, RISC-V, etc.) via portable intrinsics. No guarantees against hardware leaks (e.g., cache side-channels)—use constant-time primitives alongside.
- **Limitations**: Only affects the wrapped value; doesn't secure against copies, logs, or kernel dumps. For full protection, avoid extraction (`into_inner`) and use scoped `expose_mut()`.
- **finish_mut**: After mutations, call this to *reduce* excess capacity (for `Vec<u8>`, `String`) via `shrink_to_fit()`. This is best-effort—some allocators may not shrink—and does *not* overwrite freed memory (old secrets may persist until allocator/OS reuse). Zeroization on drop still covers only the used portion (up to `.len()`).
- **Dynamic Container Caveats**: For growable types like `Vec<u8>` or `String`, safe Rust cannot zero the full historical capacity (e.g., after `truncate` or realloc). Only the current slice up to `.len()` is overwritten on drop. Avoid patterns like filling a large buffer with secrets then truncating to small length—opt for fixed-size where possible or explicitly zero excess via `expose_mut().fill(0)` before shrinking.
- **Fallback Mode**: Disabled without `zeroize` feature—treat as plain `Box<T>`.

For details, see [zeroize docs](https://docs.rs/zeroize).

## Contribution

Contributions welcome! Please submit PRs with tests/fuzz targets.

## License

Licensed under MIT OR Apache-2.0