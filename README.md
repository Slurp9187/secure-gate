# secure-gate

[![Crates.io](https://img.shields.io/crates/v/secure-gate.svg)](https://crates.io/crates/secure-gate)
[![Docs.rs](https://docs.rs/secure-gate/badge.svg?version=0.8.0)](https://docs.rs/secure-gate/0.8.0/secure_gate/)
[![CI](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml/badge.svg?branch=release%2F0.8)](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml?query=branch%3Arelease%2F0.8)
[![MSRV: 1.70](https://img.shields.io/badge/msrv-1.70-blue)](https://github.com/Slurp9187/secure-gate/blob/release/0.8/Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Secure wrappers for secrets with **explicit access** and **mandatory zeroization** — a `no_std`-compatible, zero-overhead library with audit-friendly access patterns.

> [!NOTE]
> This is the **0.8 line** (`release/0.8`): Rust edition 2021, **MSRV 1.70**, for projects
> that cannot yet move to Rust 1.87. It has the API of 0.9 (`main`) without the `sealed`
> feature, which needs Rust 1.85. On Rust 1.87 or newer, use 0.9.

> [!WARNING]
> **Security Notice**: This crate has **not undergone independent audit**.
> Review the code and [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/release/0.8/SECURITY.md) before production use.

## A guardrail, not a vault

secure-gate stops the ordinary mistakes: a secret printed by `{:?}`, compared with `==`,
left in freed memory, or handed out as a plain `Vec`. It cannot stop someone who decides
to copy a secret out; a secret nobody can read is useless. So:

- **The easy path is safe.** The obvious way to hold, decode, encode or compare a secret
  keeps it wrapped, wiped and redacted.
- **Reaching it is named.** Every way to the secret, from the scoped `with_secret` to the
  exits (`expose_secret`, `into_inner`, `into_zeroizing`, `as_reader`), is a call you can
  grep for and a reviewer can see.

Don't route around it with `.to_vec()`, `*bytes` or `.to_string()`; name the exit instead.

## Installation

```toml
[dependencies]
secure-gate = "0.8"                                                             # default: heap on (`alloc`)
# secure-gate = { version = "0.8", default-features = false }                  # heap off: `Fixed` only
# secure-gate = { version = "0.8", features = ["full"] }                       # batteries included
```

On Rust 1.87 or newer, use `secure-gate = "0.9"` (the `main` line), which adds `sealed`.
<!-- Every concrete version in this file equals the version in Cargo.toml; bump them in the
     same commit. The install lines use the caret form and carry no patch version. -->

## Quick start

```rust
use secure_gate::{ConstantTimeEq, Dynamic, RevealSecret, RevealSecretMut, ToHex};
use secure_gate::{dynamic_newtype, fixed_newtype};

// A secret type is a visibility, a name, a size (or an inner type), and a doc string.
fixed_newtype!(pub EncKey, 32, "AES-256 key. Never used for authentication.");
fixed_newtype!(pub MacKey, 32, "HMAC key. Never used for encryption.");
dynamic_newtype!(pub Password, String, "User password.");

// A plain alias gives the same protection when there is no role to confuse it with.
pub type ApiToken = Dynamic<String>;

// EncKey and MacKey are different types: a MacKey cannot be passed where an EncKey belongs.
fn seal(_enc: &EncKey, _mac: &MacKey) {}

let mut key = EncKey::from_random(); // system RNG (`rand`)
let pw: Password = "hunter2".into();
let token: ApiToken = "tok_live_123".into();
seal(&key, &MacKey::from_random());

// Nothing prints by accident (and there is no `Deref`).
assert_eq!(format!("{key:?}"), "[REDACTED]");

// Scoped access, preferred: the borrow ends with the closure, so return a verdict, not the bytes.
assert!(!pw.with_secret(|s| s.len() >= 8));
assert!(token.with_secret(|t| t.starts_with("tok_")));

// The auditable escape hatch, for FFI and third-party APIs.
assert_eq!(pw.expose_secret(), "hunter2");

// Encode and decode without leaving a wrapper (`encoding-hex`). `hex` wipes itself on drop.
let hex = key.to_hex();
let restored = EncKey::try_from_hex(&hex).expect("valid hex");

// Compare in constant time (`ct-eq`). There is no `==` on a secret.
assert!(key.ct_eq(&restored));

// An RNG you supply fills the key in place; this needs no secure-gate feature.
// (`StdRng` with a fixed seed is for the example only. Seed a real one from the system.)
use rand::{SeedableRng, TryRngCore};
let mut rng = rand::rngs::StdRng::from_seed([7u8; 32]);
let fresh = EncKey::try_new_with(|bytes| rng.try_fill_bytes(bytes)).expect("rng fill");

// Rotate in place: the old key is overwritten and never leaves the wrapper.
fresh.with_secret(|new| key.with_secret_mut(|old| old.copy_from_slice(new)));
assert!(!key.ct_eq(&restored));

// Take the plain value when ownership must transfer. Protection ends at this call.
let _raw: [u8; 32] = restored.into_inner();
// Everything still wrapped is zeroized when it drops.
```

The example needs `rand`, `ct-eq` and `encoding-hex`, all in `full`. The custom-RNG lines use
your own `rand = "0.10"` dependency; any RNG that can fill a byte slice works.

## Which type?

| You have | Use | Why |
|---|---|---|
| A key or other fixed-size secret | `fixed_newtype!(pub Name, 32, "…")` | On the stack, `no_std`, and a distinct type per role |
| A password, token or other variable-length secret | `dynamic_newtype!(pub Name, String, "…")` | On the heap (`alloc`); spare capacity is wiped too |
| A secret with no role to confuse it with | `pub type Name = Fixed<[u8; 32]>;` or `pub type Name = Dynamic<String>;` | Same protection; an alias is interchangeable with its base type |

## Features

| Feature | Adds |
|---|---|
| `alloc` _(default)_ | `Dynamic<T>`, including wiping `Vec` / `String` spare capacity |
| `std` | `std::io::Write` for `Dynamic<Vec<u8>>` and `SlotWriter`, and `Dynamic::as_reader()` (`std::io::Read`). Implies `alloc` |
| `rand` | `from_random()` (system RNG); heap-free for `Fixed`. For an RNG you supply, use `try_new_with(\|b\| rng.try_fill_bytes(b))`, which needs no feature |
| `ct-eq` | `ConstantTimeEq` via `subtle` |
| `encoding` | All of `encoding-hex`, `-base32`, `-base64`, `-bech32`; see [Encoding](#encoding) |
| `serde` | `serde-deserialize` (1 MiB default limit) and `serde-serialize` (opt-in per type via `SerializableSecret`) |
| `cloneable` | Opt-in cloning via `CloneableSecret` |
| `full` | Everything except `std` |

### `std`, `alloc` and `no_std`

There is no `no_std` feature. The crate is `no_std` whenever `std` is off, which it is by
default, and two features decide how much of the standard library it uses:

| In `Cargo.toml` | Uses | You get |
|---|---|---|
| `default-features = false` | `core` only: no heap, no OS | `Fixed` and its decoders |
| nothing (the default, `alloc`) | `core` + `alloc`: a heap, still no OS | adds `Dynamic`, the string encoders and `serde` |
| `features = ["std"]` | all of `std` | adds `std::io::Write` on `Dynamic<Vec<u8>>` and `SlotWriter`, and `Dynamic::as_reader()` |

`alloc` is the only default feature, so turning the defaults off is how you turn the heap off.
List what you still want after it:

```toml
secure-gate = { version = "0.8", default-features = false, features = ["ct-eq", "encoding-hex"] }
```

- `rand`, `ct-eq`, `cloneable` and the `encoding-*` features work without `alloc`. The
  encodings then decode into a `Fixed`; producing an encoded string needs `alloc`.
- `serde`, `serde-serialize`, `serde-deserialize` and `full` turn `alloc` on, and `std`
  turns `alloc` on.
- Cargo features only add. If any crate in your build enables `alloc` or `std` on
  `secure-gate`, it is on for the whole build.
- No wipe gets weaker or stronger with the tier. `alloc` brings `Vec` and `String` into the
  crate together with the wiping of their spare capacity. `std` changes nothing that exists
  without it; its `io::Write` on `Dynamic<Vec<u8>>` wipes each buffer it outgrows, which
  makes it the way to build a secret whose length is not known up front (see
  [SECURITY.md](SECURITY.md)).

## Encoding

Each format sits behind its own feature; `encoding` turns on all four.

| Format | Encode | Decode into `Fixed` / `Dynamic` | Feature |
|---|---|---|---|
| Hex | `ToHex` | `try_from_hex` | `encoding-hex` |
| Base32 (RFC 4648 §6) | `ToBase32` | `try_from_base32` | `encoding-base32` |
| Base64url | `ToBase64Url` | `try_from_base64url` | `encoding-base64` |
| Bech32 (BIP-173) | `ToBech32` | `try_from_bech32(s, hrp)` | `encoding-bech32` |
| Bech32m (BIP-350) | `ToBech32m` | `try_from_bech32m(s, hrp)` | `encoding-bech32` |

Every encoder returns `EncodedSecret`, which wipes itself on drop and has no `Display`.
Every decoder is fallible and decodes straight into the wrapper, as in the Quick start.

## Where protection stops

The crate wipes the buffers it owns and stops at a line you can point to. Every handoff is a
call you can grep for:

| Handoff | What you hold | Protection after it |
|---|---|---|
| `with_secret` / `with_secret_mut` | A borrow that ends with the closure | Full. A copy you make inside the closure is yours, and no lint catches it |
| `expose_secret` / `expose_secret_mut` | A reference for as long as you keep it | The wrapper still wipes; anything you copy from the reference is yours |
| `into_inner` (also on `EncodedSecret`) | The plain value | None: not wiped, not redacted |
| `to_hex` and the other encoders | An `EncodedSecret` | Wiped on drop, `Debug` redacted. `.to_string()` or `&*enc` makes a copy nothing tracks |
| `EncodedSecret::into_zeroizing` | A `Zeroizing<String>` | Wiped on drop, but it derefs to `String`, and on this line its `Debug` can print the value (`zeroize` 1.8) |
| `as_reader`, serde `Serialize` | Bytes in a buffer you or another library own | None |
| What you pass in (`"…".into()`, `try_from_hex(&s)`, `From<&[u8]>`) | Your original input | Never wrapped: only the wrapper's copy is wiped |

Beyond the handoffs:

- **No unsafe code** (`#![forbid(unsafe_code)]`).
- **Not covered:** a process that can be read (a debugger, code running in it),
  `panic = "abort"` and hard crashes, and `static` secrets.
- **Inherent limits** no wrapper removes: stack-move residue, heap-reallocation residue, and
  swap or core dumps. Each has a mitigation in SECURITY.md.

[SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/release/0.8/SECURITY.md#where-accident-prevention-ends)
has the rule that draws the line, the full threat model, and the call sites to audit.

## Stability

From 0.8.0, the public API follows semantic versioning within the 0.8 line: a 0.8.x release
adds, and does not remove or change. The promise covers the items exported from the crate
root and from `traits`, the input grammar of the macros, and each feature's name and what it
enables. Import from the crate root: the deeper module paths under `traits` (such as
`traits::reveal_secret::RevealSecret`) compile, and are not covered.

- **Features.** `full` stays as listed above. It will not grow to include `std`, so it
  remains usable on `no_std` targets.
- **MSRV.** 1.70 for the whole 0.8 line. That is what the line is for.
- **Traits.** The public traits can be implemented outside this crate, and the newtype macros
  do so. A method added to one in a 0.8.x release always comes with a default body, so
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
- [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/release/0.8/SECURITY.md): threat model and measurements.
- [CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/release/0.8/CHANGELOG.md): changes per release, including breaking ones.

**Contributing.** MSRV is 1.70, and `rust-toolchain.toml` pins it. Cargo 1.70 does not
resolve by MSRV, so dependencies whose newer releases need a newer toolchain are pinned in
`Cargo.toml`, and `Cargo.lock` is committed. What CI
checks is in [`.github/workflows/`](https://github.com/Slurp9187/secure-gate/tree/release/0.8/.github/workflows).

## License

MIT OR Apache-2.0
