# secure-gate

[![Crates.io](https://img.shields.io/crates/v/secure-gate.svg)](https://crates.io/crates/secure-gate)
[![Docs.rs](https://docs.rs/secure-gate/badge.svg)](https://docs.rs/secure-gate)
[![CI](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml)
[![MSRV: 1.87](https://img.shields.io/badge/msrv-1.87-blue)](https://github.com/Slurp9187/secure-gate/blob/main/Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Secure wrappers for secrets with **explicit access** and **mandatory zeroization** — a `no_std`-compatible, zero-overhead library with audit-friendly access patterns.

> [!WARNING]
> **Security Notice**: This crate has **not undergone independent audit**.
> Review the code and [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) before production use.

## A guardrail, not a vault

secure-gate stops the ordinary mistakes: a secret printed by `{:?}`, compared with `==`,
left in freed memory, or handed out as a plain `Vec`. It cannot stop someone who decides
to copy a secret out; a secret nobody can read is useless. So:

- **The easy path is safe.** The obvious way to hold, decode, encode or compare a secret
  keeps it wrapped, wiped and redacted.
- **Leaving it is named.** Every way out (`expose_secret`, `into_inner`, `into_zeroizing`,
  `as_reader`) is a call you can grep for and a reviewer can see.

Don't route around it with `.to_vec()`, `*bytes` or `.to_string()`; name the exit instead.

## Quick start

```rust
use secure_gate::{RevealSecret, RevealSecretMut, dynamic_newtype, fixed_newtype};

// A secret type is a visibility, a name, a size (or an inner type), and a doc string.
fixed_newtype!(pub EncKey, 32, "AES-256 key. Never used for authentication.");
fixed_newtype!(pub MacKey, 32, "HMAC key. Never used for encryption.");
dynamic_newtype!(pub Password, String, "User password.");

let mut key = EncKey::new([0xAB; 32]);
let pw: Password = "hunter2".into();

// Scoped access, preferred: the borrow ends with the closure, so return a verdict, not the bytes.
assert!(!pw.with_secret(|s| s.len() >= 8));

// Change it in place; the secret is never copied out to be modified.
key.with_secret_mut(|bytes| bytes[0] = 0);

// The auditable escape hatch, for FFI and third-party APIs.
assert_eq!(pw.expose_secret(), "hunter2");

// EncKey and MacKey are different types: a MacKey cannot be passed where an EncKey belongs.
fn seal(_enc: &EncKey, _mac: &MacKey) {}
```

Every wrapper redacts `Debug` (`[REDACTED]`), zeroizes on drop, and has no `Deref`.
`into_inner` hands the plain value back and **ends protection at that call**.

## Which type?

| You have | Use | Why |
|---|---|---|
| A key or other fixed-size secret | `fixed_newtype!(pub Name, 32, "…")` | On the stack, `no_std`, and a distinct type per role |
| A password, token or other variable-length secret | `dynamic_newtype!(pub Name, String, "…")` | On the heap (`alloc`); spare capacity is wiped too |
| A secret with no role to confuse it with | `pub type Name = Fixed<[u8; 32]>;` or `pub type Name = Dynamic<String>;` | Same protection; an alias is interchangeable with its base type |
| A long-lived key in a process that may be read while it idles | `SealedFixed` / `sealed_fixed_newtype!` (`sealed`) | Held encrypted in RAM, opened for one closure call at a time |

## Features

| Feature | Adds |
|---|---|
| `alloc` _(default)_ | `Dynamic<T>`, including wiping `Vec` / `String` spare capacity |
| `std` | `std::io::Read` / `Write` for `Dynamic<Vec<u8>>` (implies `alloc`) |
| `rand` | `from_random()` (system RNG); heap-free for `Fixed`. For an RNG you supply, use `try_new_with(\|b\| rng.try_fill_bytes(b))`, which needs no feature |
| `ct-eq` | `ConstantTimeEq` via `subtle` |
| `encoding` | All of `encoding-hex`, `-base32`, `-base64`, `-bech32` (see below) |
| `serde` | `serde-deserialize` (1 MiB default limit) and `serde-serialize` (opt-in per type via `SerializableSecret`) |
| `cloneable` | Opt-in cloning via `CloneableSecret` |
| `sealed` | `SealedFixed`, `SealedDynamic`, `sealed_fixed_newtype!` and `Prekey` (implies `std`, `rand`; adds `chacha20poly1305`, `sha2`, `guarded-block`) |
| `full` | Everything except `std` and `sealed` |

`no_std` unless `std` is enabled. `Fixed` and its decoders work without an allocator.

**Encoding.** Hex (`ToHex`), base32 (`ToBase32`), base64url (`ToBase64Url`), and bech32 or
bech32m (`ToBech32`, `ToBech32m`), each behind its own `encoding-*` feature. Encoders return
`EncodedSecret`, which wipes itself on drop; decoders (`try_from_hex` and so on) are
fallible and decode straight into the wrapper.

```rust
use secure_gate::{Fixed, ToHex};

let key: Fixed<[u8; 32]> = Fixed::new([0x42; 32]);
let hex = key.to_hex();
let back: Fixed<[u8; 32]> = Fixed::try_from_hex(&hex).expect("valid hex");
```

**Sealed memory.** With `sealed`, a key is held encrypted while it idles, under a pre-key
locked in RAM between guard pages. Each access costs about 8 µs, so it is for long-held keys,
not hot loops. What it covers and what it does not:
[`sealed`](https://docs.rs/secure-gate/latest/secure_gate/sealed/index.html).

```rust
#[cfg(feature = "sealed")]
{
    use secure_gate::{Fixed, Prekey, RevealSecret, SealedFixed};

    let prekey = Prekey::new(); // one per session; check `lock_status()`
    let key = SealedFixed::seal(Fixed::new([7u8; 32]), &prekey);
    key.with_secret(|k| assert_eq!(k[0], 7)); // decrypted for this call only
}
```

## Where protection stops

- **No unsafe code** (`#![forbid(unsafe_code)]`). The `sealed` guard pages live in the
  separate [`guarded-block`](https://crates.io/crates/guarded-block) crate.
- **Not covered:** a process that can be read (a debugger, code running in it),
  `panic = "abort"` and hard crashes, `static` secrets, copies you make inside a reveal
  closure, and whatever `into_inner` or serde `Serialize` hand out.
- **Inherent limits** no wrapper removes: stack-move residue, heap-reallocation residue, and
  swap or core dumps. Each has a mitigation in SECURITY.md.

[SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) has the full
threat model, where the crate's responsibility ends, and the call sites to audit.

## Installation

```toml
[dependencies]
secure-gate = "0.9.0-rc"                                                        # default: alloc
# secure-gate = { version = "0.9.0-rc", default-features = false }             # no heap, no_std
# secure-gate = { version = "0.9.0-rc", features = ["full"] }                  # batteries included
```

A caret requirement matches a pre-release only when it names one: `"0.9"` resolves to
nothing until 0.9.0 ships, while `"0.9.0-rc"` tracks the newest candidate. Pin
`"=0.9.0-rc.18"` when `cargo update` must stay put. On Rust older than 1.87, use
`secure-gate = "0.8.0-rc"` (the `release/0.8` line, MSRV 1.70).
<!-- Every concrete version in this file equals the version in Cargo.toml; bump them in the
     same commit. The install lines use the tracking form and carry no version. -->

## Stability

From 0.9.0, the public API follows semantic versioning within the 0.9 line: a 0.9.x release
adds, and does not remove or change. The promise covers the items exported from the crate
root and from `traits`, `sealed` and `scoped`, the input grammar of the macros, and each
feature's name and what it enables. Import from the crate root: the deeper module paths
under `traits` (such as `traits::reveal_secret::RevealSecret`) compile, and are not covered.

- **Features.** `full` stays as listed above. It will not grow to include `std` or `sealed`,
  so it remains usable on `no_std` targets.
- **MSRV.** The minimum supported Rust version rises only in a minor release (0.9 to 0.10),
  never in a patch release.
- **Traits.** The public traits can be implemented outside this crate, and the newtype macros
  do so. A method added to one in a 0.9.x release always comes with a default body, so
  existing implementations keep compiling.
- **Dependencies in the API.** Only `zeroize` and `serde`, both 1.x, appear in public
  signatures. `bech32`, `rand`, `subtle` and the other dependencies are private and can be
  upgraded without a breaking release.

## Going further

- [API docs](https://docs.rs/secure-gate): every type, trait and feature, with examples.
- [`fixed_newtype!`](https://docs.rs/secure-gate/latest/secure_gate/macro.fixed_newtype.html) and
  [`dynamic_newtype!`](https://docs.rs/secure-gate/latest/secure_gate/macro.dynamic_newtype.html):
  `generic T` inner types and opt-in conversions to and from the base wrapper.
- [`Fixed`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html): running RustCrypto
  ciphers in place inside the wrapper, and the zero-size compile error.
- [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md): threat model and measurements.
- [CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md): changes per release, including breaking ones.

**Contributing.** MSRV is 1.87; regenerate `Cargo.lock` with `cargo +1.87 update`. What CI
checks is in [`.github/workflows/`](https://github.com/Slurp9187/secure-gate/tree/main/.github/workflows).

## License

MIT OR Apache-2.0
