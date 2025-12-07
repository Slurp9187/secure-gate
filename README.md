# secure-gate

**Zero-cost, `no_std`-compatible wrappers for sensitive data with enforced explicit exposure.**

- `Fixed<T>` – stack-allocated, zero-cost wrapper  
- `Dynamic<T>` – heap-allocated wrapper with full `.into()` ergonomics  
- `FixedRng<N>` – cryptographically secure random bytes of exact length N  
- `RandomHex` – validated random hex string that can only be constructed from fresh RNG

When the `zeroize` feature is enabled, secrets are automatically wiped on drop (including spare capacity).

**All access to secret bytes now requires an explicit `.expose_secret()` call** – no silent leaks, no `Deref`, no hidden methods.

## Installation

```toml
[dependencies]
secure-gate = "0.6.0"
```

**Recommended (maximum safety + ergonomics):**

```toml
secure-gate = { version = "0.6.0", features = ["zeroize", "rand", "conversions"] }
```

## Features

| Feature       | Description                                                                                 |
|---------------|---------------------------------------------------------------------------------------------|
| `zeroize`     | Automatic memory wiping on drop — **strongly recommended**                                  |
| `rand`        | `FixedRng<N>::generate()` + `fixed_alias_rng!` — type-safe, fresh randomness                |
| `conversions` | `.to_hex()`, `.to_hex_upper()`, `.to_base64url()`, `.ct_eq()` + `HexString` / `RandomHex`   |

Works in `no_std` + `alloc`. Only pay for what you use.

## Quick Start – v0.6.0

```rust
use secure_gate::{fixed_alias, dynamic_alias, fixed_alias_rng};

fixed_alias!(Aes256Key, 32);
dynamic_alias!(Password, String);

// Type-safe, guaranteed-fresh randomness
#[cfg(feature = "rand")]
{
    fixed_alias_rng!(MasterKey, 32);
    fixed_alias_rng!(Nonce, 24);

    let key   = MasterKey::generate(); // FixedRng<32>
    let nonce = Nonce::generate();     // FixedRng<24>

    #[cfg(feature = "conversions")]
    let hex_token: RandomHex = MasterKey::random_hex(); // only from fresh RNG
}

// Secure conversions — explicit exposure is mandatory
#[cfg(all(feature = "rand", feature = "conversions"))]
{
    let key   = MasterKey::generate();
    let other = MasterKey::generate();

    let hex  = key.expose_secret().to_hex();           // "a1b2c3d4..."
    let b64  = key.expose_secret().to_base64url();     // URL-safe, no padding
    let same = key.expose_secret().ct_eq(other.expose_secret()); // constant-time

    println!("Key (hex):       {hex}");
    println!("Key (Base64URL): {b64}");
}

// Heap secrets — unchanged ergonomics
let pw: Password = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");
```

## Type-Safe Randomness (v0.6.0)

```rust
#[cfg(feature = "rand")]
{
    fixed_alias_rng!(JwtSigningKey, 32);
 fixed_alias_rng!(BackupCode, 16);

 let key  = JwtSigningKey::generate();   // FixedRng<32>
 let code = BackupCode::generate();      // FixedRng<16>

 #[cfg(feature = "conversions")]
 let hex_code: RandomHex = BackupCode::random_hex();
 println!("Backup code: {}", hex_code.expose_secret());
}
```

- **Guaranteed freshness** – `FixedRng<N>` can only be constructed via secure RNG  
- **Zero-cost** – newtype over `Fixed`, fully inlined  
- `.generate()` is the canonical constructor (`.new()` is deliberately unavailable)

## Secure Conversions — `conversions` feature (v0.6.0)

```rust
#[cfg(all(feature = "rand", feature = "conversions"))]
{
    fixed_alias_rng!(Aes256Key, 32);
    let key   = Aes256Key::generate();
    let other = Aes256Key::generate();

    let hex  = key.expose_secret().to_hex();           // "a1b2c3d4..."
    let b64  = key.expose_secret().to_base64url();     // URL-safe, no padding
    let same = key.expose_secret().ct_eq(other.expose_secret()); // constant-time
}
```

**Why `.expose_secret()` is required**  
Every secret access is now loud, grep-able, and auditable. There are **no** methods on the wrapper types that expose the bytes directly.

## Macros

```rust
fixed_alias!(Aes256Key, 32);
dynamic_alias!(Password, String);

#[cfg(feature = "rand")]
fixed_alias_rng!(MasterKey, 32);   // FixedRng<32>
```

## Memory Guarantees (`zeroize` enabled)

| Type            | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes                     |
|-----------------|------------|-----------|-----------|------------------|---------------------------|
| `Fixed<T>`      | Stack      | Yes       | Yes       | Yes (no heap)    | Zero-cost                 |
| `Dynamic<T>`    | Heap       | Yes       | Yes       | No (until drop)  | Use `finish_mut()`        |
| `FixedRng<N>`   | Stack      | Yes       | Yes       | Yes              | Fresh + type-safe         |
| `RandomHex`     | Heap       | Yes       | Yes       | No (until drop)  | Validated random hex      |

## Performance – v0.6.0 (Measured December 2025)

Benchmarked on:  
**Windows 11 Pro, Intel Core i7-10510U @ 1.80 GHz, 16 GB RAM, Rust 1.88.0 (2025-06-23)**

`cargo bench -p secure-gate --all-features`

| Implementation                              | Time per access (100 samples)       | Δ vs raw array                     |
|---------------------------------------------|-------------------------------------|------------------------------------|
| raw `[u8; 32]` access                       | 492.22 ps – 501.52 ps               | baseline                           |
| `Fixed<[u8; 32]>` + `.expose_secret()`      | 476.92 ps – 487.12 ps               | −3.0 % to −23.9 %                   |
| `fixed_alias! (RawKey` explicit access     | 475.07 ps – 482.91 ps               | −3.4 % to −30.5 %                   |

All implementations are statistically indistinguishable from raw arrays at the picosecond level — even on a 2019-era mobile CPU.  
The explicit `.expose_secret()` path incurs **no measurable overhead**.

[View full Criterion report](https://slurp9187.github.io/secure-gate/benches/fixed_vs_raw/report/)

## Changelog

[CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License

MIT OR Apache-2.0

---

**v0.6.0 is a breaking security-hardening release.**  
All secret access is now explicit. No silent leaks remain.