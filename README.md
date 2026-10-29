# secure-gate

[![Crates.io](https://img.shields.io/crates/v/secure-gate.svg)](https://crates.io/crates/secure-gate)
[![Docs.rs](https://docs.rs/secure-gate/badge.svg)](https://docs.rs/secure-gate)
[![CI](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/Slurp9187/secure-gate/actions/workflows/ci.yml)
[![MSRV: 1.85](https://img.shields.io/badge/msrv-1.85-blue)](https://github.com/Slurp9187/secure-gate/blob/main/Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Secure wrappers for secrets with **explicit access** and **mandatory zeroization** — a `no_std`-compatible, zero-overhead library with audit-friendly access patterns.

> [!WARNING]
> **Security Notice**: This crate has **not undergone independent audit**.
> Review the code and [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) before production use.

## Quick start

```rust
use secure_gate::{RevealSecret, RevealSecretMut, dynamic_newtype, fixed_newtype};

// A secret type is a visibility, a name, a size (or an inner type), and a doc string.
fixed_newtype!(pub Aes256Key, 32, "AES-256 key. On the stack, exactly 32 bytes.");
dynamic_newtype!(pub Password, String, "User password. On the heap, length varies with the input.");

let mut pw: Password = "hunter2".into();
let mut key: Aes256Key = Aes256Key::from_random(); // system RNG (`rand` feature)

// Scoped access — preferred: the borrow cannot outlive the closure, so return a verdict,
// never the bytes.
let long_enough = pw.with_secret(|s| s.len() >= 8);

// Mutate in place — the old key is overwritten and never leaves the wrapper.
let next: Aes256Key = Aes256Key::from_random();
next.with_secret(|fresh| key.with_secret_mut(|old| old.copy_from_slice(fresh)));

// Direct reference — the auditable escape hatch (FFI, third-party APIs).
assert_eq!(pw.expose_secret(), "hunter2");
pw.expose_secret_mut().clear();

#[cfg(feature = "encoding-hex")]
{
    use secure_gate::ToHex;
    let hex = key.with_secret(|bytes| bytes.to_hex()); // `EncodedSecret`: wiped on drop
    let decoded = Aes256Key::try_from_hex(&hex).expect("valid hex"); // straight into the wrapper
    decoded.with_secret(|d| key.with_secret(|original| assert_eq!(d, original)));
}
```

## Which type?

| You have | Use | Why |
|---|---|---|
| A key or other fixed-size secret | `fixed_newtype!(pub Name, 32, "…")` | Stack-allocated, `no_std`, and a distinct type per role, so an encryption key cannot be passed where a MAC key belongs |
| A password, token or other variable-length secret | `dynamic_newtype!(pub Name, String, "…")` | Heap-allocated (`alloc`); spare capacity is wiped too |
| A secret with no role to confuse it with | `pub type Name = Fixed<[u8; 32]>;` | A plain alias: same protection, interchangeable with its base type |
| A long-lived key in a process that may be read while it idles | `SealedFixed` / `sealed_fixed_newtype!` (`sealed`) | Held encrypted in RAM, opened for one closure call at a time; see [Sealed memory](#sealed-memory) |

Every wrapper redacts `Debug` (`[REDACTED]`), zeroizes on drop, has no `Deref`, and is read
only through `with_secret` (scoped, preferred) or `expose_secret` (an escape hatch you can
grep for). `into_inner` hands the plain value back and **ends protection at that call**.

## Access, and keeping the secret inside the wrapper

```rust
use secure_gate::{Fixed, RevealSecret, RevealSecretMut};

let mut key: Fixed<[u8; 32]> = Fixed::new([0xAB; 32]);

// Read: validate inside the closure and return only the verdict.
let degenerate = key.with_secret(|bytes| bytes.iter().all(|&b| b == bytes[0]));
assert!(degenerate);

// Write: the secret is never copied out to be modified.
key.with_secret_mut(|bytes| bytes.copy_from_slice(&[0xCD; 32]));

// Move it out when ownership must transfer. Protection ends here; nothing was copied.
let owned: [u8; 32] = key.into_inner();
assert_eq!(owned, [0xCD; 32]);
```

RustCrypto ciphers can run *inside* the wrapper: `GenericArray::from_mut_slice` borrows
rather than copies, so the plaintext never leaves it.

```rust
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
use secure_gate::{Fixed, RevealSecretMut};

let cipher = Aes128::new(GenericArray::from_slice(&[0x42u8; 16]));
let mut block: Fixed<[u8; 16]> = Fixed::new([0u8; 16]);
block.with_secret_mut(|b| cipher.decrypt_block(GenericArray::from_mut_slice(b)));
```

Copying out instead (`block.with_secret(|b| aes::Block::from(*b))`) leaves an ordinary stack
value that nothing wipes. A copy made *inside* a reveal closure is the caller's: no lint
catches it ([SECURITY.md §4](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md#4-copying-the-secret-out-of-a-reveal-borrow)).

## Named secret types

Newtypes are `struct`s, so two of the same shape are **different types**:

```rust
use secure_gate::fixed_newtype;

fixed_newtype!(pub EncKey, 32, "AES-256 key. Never used for authentication.");
fixed_newtype!(pub MacKey, 32, "HMAC-SHA256 key. Never used for encryption.");

fn seal(enc: &EncKey, mac: &MacKey) { /* … */ }
// seal(&mac, &enc) does not compile: the roles cannot be swapped by accident.
```

A plain `type` alias is a name and nothing more: two aliases over `Fixed<[u8; 32]>` are one
type, and the compiler will not keep them apart. To find aliases that share a base type in a
tree you already have (each group with more than one name is a newtype candidate if its
names mean different things):

```sh
grep -rhoE '\btype +[A-Za-z0-9_]+ *= *(Fixed|Dynamic)<.*>;' src/ \
 | sed -E 's/type +([A-Za-z0-9_]+) *= *(.+);/\2\t\1/' | sort \
 | awk -F'\t' '{ a[$1] = a[$1] " " $2; n[$1]++ }
              END { for (b in a) if (n[b] > 1) printf "%-24s %d names:%s\n", b, n[b], a[b] }'
```

The macros also take `generic T` for inner types that are neither bytes nor a string (an
ML-KEM polynomial, say), and opt-in conversions to and from the base wrapper; see
[`fixed_newtype!`](https://docs.rs/secure-gate/latest/secure_gate/macro.fixed_newtype.html)
and [`dynamic_newtype!`](https://docs.rs/secure-gate/latest/secure_gate/macro.dynamic_newtype.html).
A zero-sized `Fixed` is a compile error; where that error fires, and where it does not, is in
[`Fixed`'s docs](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html#zero-size).

## Sealed memory

With the `sealed` feature, a secret can be held **encrypted** in RAM while it idles and opened
for one closure call at a time. A lossy readout of memory (cold boot, Rowhammer,
Spectre-class leaks) that gets one bit of the 16 KiB pre-key wrong yields a useless key, and
a sealed secret paged to swap cannot be opened from there, because the pre-key is locked in
RAM. The pre-key lives in memory of its own between no-access guard pages, off the heap, so a
buffer over-read in the process (C code, Heartbleed-style) that runs into it faults instead of
reading it.

```rust
#[cfg(feature = "sealed")]
{
    use secure_gate::{Fixed, Prekey, RevealSecret, SealedFixed, fixed_newtype, sealed_fixed_newtype};

    // One pre-key per session: create it at login, drop it (and everything sealed under
    // it) at logout. Its lock can be refused (a quota), which is reported, never fatal.
    let prekey = Prekey::new();
    if let Err(why) = prekey.lock_status() {
        eprintln!("pre-key not locked in RAM: {why}");
    }

    let key = SealedFixed::seal(Fixed::new([7u8; 32]), &prekey);
    key.with_secret(|k| assert_eq!(k[0], 7)); // decrypted for this call only

    // Sealed roles keep newtypes apart, as their plain counterparts do.
    fixed_newtype!(pub AppKey, 32, "The application key.");
    sealed_fixed_newtype!(pub SealedAppKey, AppKey, "The application key, sealed.");
    let app = SealedAppKey::seal(AppKey::new([9u8; 32]), &prekey);
    app.with_secret(|k| assert_eq!(k[31], 9));
}
```

Each access costs about 8 µs (it hashes the pre-key) and 32 KiB of stack, so sealing is for
long-held keys, not hot loops. `Prekey::new_idle_noaccess()` also makes the pre-key
unreadable between accesses (unless the system refuses that change, in exhaustion cases),
which on Windows keeps it out of crash dumps but costs its lock.
What it covers and what it does not:
[`sealed`](https://docs.rs/secure-gate/latest/secure_gate/sealed/index.html) and
[SECURITY.md §3](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md#3-swap--core-dumps--external-memory-exposure).

## Encoding

Hex, base32 (RFC 4648 §6), base64url, bech32 (BIP-173) and bech32m (BIP-350), each behind its
own feature. Every encoder returns `EncodedSecret`, which wipes itself on drop and has no
`Display`; every decoder is fallible and stages into wiping buffers.

| Format | Encode | Decode into `Fixed` / `Dynamic` | Feature |
|---|---|---|---|
| Hex | `ToHex` | `try_from_hex` | `encoding-hex` |
| Base32 | `ToBase32` | `try_from_base32` | `encoding-base32` |
| Base64url | `ToBase64Url` | `try_from_base64url` | `encoding-base64` |
| Bech32 / Bech32m | `ToBech32` / `ToBech32m` | `try_from_bech32(s, hrp)` / `try_from_bech32m(s, hrp)` | `encoding-bech32` |

```rust
use secure_gate::{Case, Fixed, ToBech32, ToHex};
# fn main() -> Result<(), secure_gate::Bech32Error> {
let key: Fixed<[u8; 32]> = Fixed::new([0x42u8; 32]);
let hex = key.to_hex();
let b32 = key.try_to_bech32("key", Case::Lower)?;
let back: Fixed<[u8; 32]> = Fixed::try_from_hex(&hex).expect("valid hex");
# Ok(())
# }
```

Prefer the HRP-checked bech32 decoders; the `_unchecked` forms are for an HRP validated
upstream.

## Security at a glance

- **No unsafe code**: `#![forbid(unsafe_code)]`. (The `sealed` pre-key's page protection is in
  [`guarded-block`](https://crates.io/crates/guarded-block), a separate crate from this
  repository.)
- **Constant-time equality** with `ct-eq` (`subtle`). Equality timing is the only side channel
  in scope.
- **Not covered**: a process that can be read (debugger, code running in it), `panic = "abort"`
  and hard crashes, `static` secrets, copies the caller makes, and what `into_inner` or serde
  `Serialize` hand out.
- **Inherent limits** that no wrapper removes: stack-move residue (mitigated by `new_with` and
  passing by reference), heap-reallocation residue (pre-size buffers, or install
  [`zeroizing-alloc`](https://crates.io/crates/zeroizing-alloc) in your application), and
  swap or core dumps (operating-system controls, or `sealed`).

[SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) has the full
threat model, the measurements behind it, and the call sites to audit.

## Installation

```toml
[dependencies]
secure-gate = "0.9.0-rc"                                                        # default: alloc
# secure-gate = { version = "0.9.0-rc", default-features = false }             # no heap, no_std
# secure-gate = { version = "0.9.0-rc", features = ["full"] }                  # batteries included
```

Both release lines are pre-release only, and a caret requirement matches a pre-release only
when it names one: `"0.9"` resolves to nothing, while `"0.9.0-rc"` tracks the newest
`0.9.0-rc.N` and keeps resolving once `0.9.0` ships. Release candidates have carried breaking
changes, so pin `"=0.9.0-rc.16"` when `cargo update` must stay put.
<!-- Every concrete version in this file equals the version in Cargo.toml; bump them in the
     same commit. The install lines use the tracking form and carry no version. -->

| Branch | Version | Edition | MSRV | Status |
|---|---|---|---|---|
| `main` | 0.9.x | 2024 | 1.85 | Active development |
| `release/0.8` | 0.8.x | 2021 | 1.70 | Same API as of 0.8.0-rc.14; a final backport follows 0.9.0 stable |

On Rust older than 1.85, use `secure-gate = "0.8.0-rc"`. Changes per release, including the
breaking ones, are in [CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md).

## Features

| Feature | Adds |
|---|---|
| `alloc` _(default)_ | `Dynamic<T>`, including wiping `Vec` / `String` spare capacity |
| `std` | `std::io::Read` / `Write` for `Dynamic<Vec<u8>>` (implies `alloc`) |
| `rand` | `from_random()` (system RNG); heap-free for `Fixed`. For an RNG you supply, use `try_new_with(\|b\| rng.try_fill_bytes(b))`, which needs no feature |
| `ct-eq` | `ConstantTimeEq` via `subtle` |
| `encoding` | All of `encoding-hex`, `-base32`, `-base64`, `-bech32` |
| `serde` | `serde-deserialize` (1 MiB default limit) and `serde-serialize` (opt-in per type via `SerializableSecret`) |
| `cloneable` | Opt-in cloning via `CloneableSecret` |
| `sealed` | `SealedFixed`, `SealedDynamic`, `sealed_fixed_newtype!` and `Prekey` (implies `std`, `rand`; adds `chacha20poly1305`, `sha2`, `guarded-block`) |
| `full` | Everything except `std` and `sealed` |

`no_std` unless `std` is enabled, checked in CI by building for `thumbv7em-none-eabihf`.
`Fixed` and its decoders work without an allocator.

## Moving from `secrecy`

`secrecy` 0.10's only wrapper is the heap `SecretBox`. `Fixed<T>` is the inline,
stack-capable counterpart, kept for `no_std` and speed; for a long-held secret prefer
`Dynamic` or a sealed type. (The experimental `secure-gate-compat` shim was never published;
`git checkout v0.9.0-rc.8 -- secure-gate-compat` restores it.)

## Contributing

MSRV is 1.85; regenerate `Cargo.lock` with `cargo +1.85 update`. CI runs lint, tests across
feature combinations, rustdoc with `--all-features` (the docs.rs set, and the documentation
contract), the MSRV, AddressSanitizer, and fuzz targets; see
[`.github/workflows/`](.github/workflows/).

## License

MIT OR Apache-2.0
