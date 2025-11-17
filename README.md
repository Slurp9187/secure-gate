# secure-gate

A zero-overhead, `no_std`-compatible secret wrapper with automatic zeroization.

## Key Features Summary

`secure-gate` is designed for seamless, safe secret handling with **zero runtime overhead** when features are disabled. Core highlights:

- **Auto-Gating**: Switches between `SecretBox<T>` + zeroization (default `zeroize` feature) and plain `Box<T>` fallback for minimal builds—no code changes required.
- **No-Std Native**: Full `no_std` + `alloc` support for embedded systems.
- **Safe & Ergonomic**: All public API in 100% safe Rust; `secure!` macro for quick construction; aliases like `SecurePassword` (immutable default), `SecurePasswordBuilder` (mutable opt-in), and `SecureKey32`.
- **Redacted & Zeroized**: Automatic `Debug` redaction (`"[REDACTED]"`); best-effort zeroization on drop/mutation via `zeroize`.
- **Serde-Ready**: Opt-in serialization of secrets (explicitly exposes the secret in serialized form, e.g., JSON strings; protect output bytes appropriately).
- **Fuzz-Hardened**: 5 libFuzzer targets running 300 CPU minutes nightly.
- **Zero-Alloc Fixed Secrets**: Stack-only types for keys/nonces (default via `stack` feature) — no heap, cache-local, `#![no_global_oom]` friendly.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
secure-gate = "0.3.2"
```

## Usage

```rust
use secure_gate::{SecurePassword, SecurePasswordBuilder, Secure};

let password: SecurePassword = "hunter2".into();  // Immutable default, zeroized on drop

let key = Secure::<[u8; 32]>::new(rand::random());  // generic fixed-size (heap for dynamic fallbacks)
let token = Secure::<Vec<u8>>::new(vec![...]);  // dynamic buffer

// Scoped mutation (preferred for mutable cases)
let mut pw_mut: SecurePasswordBuilder = SecurePasswordBuilder::new("base".to_string());
pw_mut.expose_mut().expose_secret_mut().push_str("!!!");
pw_mut.finish_mut();  // reduce excess capacity via shrink_to_fit (best-effort; no scrub of freed memory)

// Convert to immutable form (zeroizes the builder)
let pw: SecurePassword = pw_mut.into_password();  // or .build()

// Extraction (use sparingly)
let bytes: Vec<u8> = token.into_inner();  // original zeroized immediately
```

**Note:** `SecurePasswordMut` is deprecated in v0.3.1 — use `SecurePasswordBuilder` instead.

### Zero-Allocation Fixed-Size Secrets (Default)

For keys/nonces/IVs, aliases like `SecureKey32` default to stack-only `Zeroizing<[u8; N]>` — no heap, deterministic, side-channel minimal:

```rust
use secure_gate::{SecureKey32, SecureNonce12};
use secure_gate::stack::{key32, nonce12};

static AES_KEY: SecureKey32 = key32([0x42; 32]);  // const-eligible!
let key: SecureKey32 = SecureKey32::new(rand::random::<[u8; 32]>());  // from RNG
let nonce: SecureNonce12 = nonce12([0u8; 12]);

// Access: deref to inner slice/array
assert_eq!(&*key, &[0x42; 32]);
```

Falls back to `Secure<[u8; N]>` if `stack` disabled. Ideal for crypto hot paths (rustls/ring-style).

### Fuzzing Configuration

| Target    | Description                                      | Runtime per CI run |
|-----------|--------------------------------------------------|--------------------|
| `expose`  | Memory access + `finish_mut`                     | 60 minutes         |
| `clone`   | `init_with`, `into_inner`, scoped zeroization    | 60 minutes         |
| `serde`   | JSON + bincode deserialization from untrusted input | 60 minutes      |
| `parsing` | `FromStr` parsing                                | 60 minutes         |
| `mut`     | Unbounded `expose_mut()` mutation stress         | 60 minutes         |

- 5 libFuzzer targets running nightly
- 300 CPU minutes of continuous fuzzing on GitHub Actions

## Dependencies

```toml
[dependencies]
secrecy = { version = "0.10.3", optional = true, default-features = false }
zeroize = { version = "1.8", optional = true, default-features = false, features = [
  "alloc",
  "zeroize_derive",
] }
serde = { version = "1.0", features = ["derive"], optional = true }
```

## Features

| Feature       | Effect                                              |
|---------------|-----------------------------------------------------|
| `zeroize`     | Enables `SecretBox<T>` + zeroization on drop (default) |
| **`stack`**   | **Zero-alloc fixed-size types** (`Zeroizing<[u8; N]>` for `SecureKey32` etc.; default) |
| `serde`       | Adds `Serialize` / `Deserialize` impls              |
| `unsafe-wipe` | **Opt-in** fast zeroization for `Secure<String>` (no allocation, preserves len/cap; requires `zeroize`). Disables `#![forbid(unsafe_code)]` for this path—safe usage (only overwrites used buffer with zeros; null bytes valid UTF-8). Use for performance-critical secrets; stick to safe path otherwise. |
| `full`        | Enables `zeroize` + `serde` + `unsafe-wipe`         |

## Zeroization Guarantees

`Secure<T>` provides **best-effort memory zeroization** on drop/mutation via the `zeroize` crate:

- **What It Does**: Explicitly overwrites secret bytes (up to `.len()` for dynamic types like `Vec`/`String`) using volatile operations that resist compiler optimization.
- **Platform Coverage**: Works on all stable Rust targets (x86, ARM, RISC-V, etc.) via portable intrinsics. No guarantees against hardware leaks (e.g., cache side-channels)—use constant-time primitives alongside.
- **Limitations**: Only affects the wrapped value; doesn't secure against copies, logs, or kernel dumps. For full protection, avoid extraction (`into_inner`) and use scoped `expose_mut()`.
- **finish_mut**: After mutations, call this to *reduce* excess capacity (for `Vec<u8>`, `String`) via `shrink_to_fit()`. This is best-effort—some allocators may not shrink—and does *not* overwrite freed memory (old secrets may persist until allocator/OS reuse). Zeroization on drop still covers only the used portion (up to `.len()`).
- **Dynamic Container Caveats**: For growable types like `Vec<u8>` or `String`, safe Rust cannot zero the full historical capacity (e.g., after `truncate` or realloc). Only the current slice up to `.len()` is overwritten on drop. Avoid patterns like filling a large buffer with secrets then truncating to small length—opt for fixed-size where possible or explicitly zero excess via `expose_mut().fill(0)` before shrinking.
- **Unsafe-Wipe Fast Path**: When enabled, `Secure<String>` uses `unsafe` for zero-allocation wiping (preserves len/cap)—safe for used buffer only. Null bytes are valid UTF-8; no invariants broken. Opt-in for performance (e.g., high-frequency secrets); safe path used otherwise (allocates temp zeros).
- **Fallback Mode**: Disabled without `zeroize` feature—treat as plain `Box<T>`.
- **Stack Aliases Note**: Fixed-size types like `SecureKey32` use `Zeroizing<[u8; N]>` by default (via `stack` feature) for zero-overhead zeroization — same guarantees, no heap.

For details, see [zeroize docs](https://docs.rs/zeroize).

## Contribution

Contributions welcome! Please submit PRs with tests/fuzz targets.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.

## License

Licensed under MIT OR Apache-2.0