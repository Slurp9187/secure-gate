# secure-gate  
**Zero-cost, `no_std`-compatible wrappers for sensitive data with enforced explicit exposure.**

- `Fixed<T>` – Stack-allocated, zero-cost wrapper  
- `Dynamic<T>` – Heap-allocated wrapper with full `.into()` ergonomics
- `FixedRng<N>` – Cryptographically secure random bytes of exact length N  
- `RandomHex` – Validated random hex string that can only be constructed from fresh RNG

When the `zeroize` feature is enabled, secrets are automatically wiped on drop (including spare capacity).  
**All access to secret bytes requires an explicit `.expose_secret()` call** – no silent leaks, no `Deref`, no hidden methods, no `into_inner()` bypasses.

## Installation  
```toml
[dependencies]
secure-gate = "0.6.1"
```

**Recommended (maximum safety + ergonomics):**  
```toml
secure-gate = { version = "0.6.1", features = ["zeroize", "rand", "conversions"] }
```

## Features  
| Feature | Description |  
|---------------|---------------------------------------------------------------------------------------------|  
| `zeroize` | Automatic memory wiping on drop – **strongly recommended** |  
| `rand` | `FixedRng<N>::generate()` + `fixed_alias_rng!` – type-safe, fresh randomness |  
| `conversions` | `.to_hex()`, `.to_hex_upper()`, `.to_base64url()`, `.ct_eq()` + `HexString` / `RandomHex` |  

Works in `no_std` + `alloc`. Only pay for what you use.

## Quick Start  
```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub Aes256Key, 32);       // Explicit visibility required
dynamic_alias!(pub Password, String);   // Explicit visibility required

#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;

    fixed_alias_rng!(pub MasterKey, 32);  // Explicit visibility required
    fixed_alias_rng!(pub Nonce, 24);      // Explicit visibility required
    let key = MasterKey::generate();      // FixedRng<32>
    let nonce = Nonce::generate();        // FixedRng<24>
    
    #[cfg(feature = "conversions")]
    {
        use secure_gate::RandomHex;

        let hex_token: RandomHex = MasterKey::random_hex(); // Only from fresh RNG
    }
}

// Heap secrets – unchanged ergonomics  
let pw: Password = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");
```

## Type-Safe Randomness  
```rust
#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;

    fixed_alias_rng!(pub JwtSigningKey, 32);   // Explicit visibility required
    fixed_alias_rng!(pub BackupCode, 16);       // Explicit visibility required
    let key = JwtSigningKey::generate();        // FixedRng<32>
    let code = BackupCode::generate();          // FixedRng<16>
    
    #[cfg(feature = "conversions")]
    {
        use secure_gate::RandomHex;

        let hex_code: RandomHex = BackupCode::random_hex();
        println!("Backup code: {}", hex_code.expose_secret());
    }
}
```

- **Guaranteed freshness** – `FixedRng<N>` can only be constructed via secure RNG  
- **Zero-cost** – Newtype over `Fixed`, fully inlined  
- **Explicit visibility** – All macros require clear visibility specification (`pub`, `pub(crate)`, or private)
- `.generate()` is the canonical constructor (`.new()` is deliberately unavailable)

### Converting RNG Types

When you need to convert `FixedRng` or `DynamicRng` to their base types:

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{Fixed, Dynamic, rng::{FixedRng, DynamicRng}};
    
    // Convert FixedRng to Fixed (preserves security guarantees)
    let key: Fixed<[u8; 32]> = FixedRng::<32>::generate().into();
    // Or explicitly:
    let key: Fixed<[u8; 32]> = FixedRng::<32>::generate().into_inner();
    
    // Convert DynamicRng to Dynamic
    let random: Dynamic<Vec<u8>> = DynamicRng::generate(64).into();
}
```

### Direct Random Generation

For convenience, you can generate random secrets directly without going through `FixedRng`:

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{Fixed, Dynamic};
    
    // Direct generation (most ergonomic)
    let key: Fixed<[u8; 32]> = Fixed::generate_random();
    let random: Dynamic<Vec<u8>> = Dynamic::generate_random(64);
    
    // Equivalent to:
    // FixedRng::<32>::generate().into()  // or .into_inner() which returns Fixed
    // DynamicRng::generate(64).into()    // or .into_inner() which returns Dynamic
}
```

**Note**: `FixedRng`/`DynamicRng` preserve the type-level guarantee that values came from RNG. Converting to `Fixed`/`Dynamic` loses that guarantee but enables mutation if needed.  

## Secure Conversions – `conversions` feature  
```rust  
#[cfg(all(feature = "rand", feature = "conversions"))]
{
    use secure_gate::fixed_alias_rng;
    use secure_gate::SecureConversionsExt;

    fixed_alias_rng!(pub Aes256Key, 32);  // Explicit visibility required
    let key = Aes256Key::generate();
    let other = Aes256Key::generate();
    let hex = key.expose_secret().to_hex();          // "a1b2c3d4..."
    let b64 = key.expose_secret().to_base64url();    // URL-safe, no padding  
    let same = key.expose_secret().ct_eq(other.expose_secret()); // Constant-time
}
```

**Why `.expose_secret()` is required**  
Every secret access is loud, grep-able, and auditable. There are **no** methods on the wrapper types that expose bytes directly. The security model is strictly enforced: `Fixed<T>`, `Dynamic<T>`, `FixedNoClone<T>`, and `DynamicNoClone<T>` do not provide `into_inner()` methods that would bypass the explicit exposure requirement. This ensures all secret access is traceable and prevents accidental security violations.

## Macros  
```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(pub Aes256Key, 32);           // Public type
fixed_alias!(private_key, 32);             // Private type (no visibility modifier)  
fixed_alias!(pub(crate) InternalKey, 64);  // Crate-visible type

dynamic_alias!(pub Password, String);       // Public type

#[cfg(feature = "rand")]
{
    use secure_gate::fixed_alias_rng;

    fixed_alias_rng!(pub MasterKey, 32);    // FixedRng<32>  
}
```

## Memory Guarantees (`zeroize` enabled)  
| Type | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes |  
|-----------------|------------|-----------|-----------|------------------|---------------------------|  
| `Fixed<T>` | Stack | Yes | Yes | Yes (no heap) | Zero-cost |  
| `Dynamic<T>` | Heap | Yes | Yes | No (until drop) | Use `expose_secret_mut().shrink_to_fit()` |  
| `FixedRng<N>` | Stack | Yes | Yes | Yes | Fresh + type-safe |  
| `RandomHex` | Heap | Yes | Yes | No (until drop) | Validated random hex |  

## Performance (Measured December 2025)  
Benchmarked on:  
**Windows 11 Pro, Intel Core i7-10510U @ 1.80 GHz, 16 GB RAM, Rust 1.88.0 (2025-06-23)**  
`cargo bench -p secure-gate --all-features`  

| Implementation | Time per access (100 samples) | Δ vs raw array |  
|---------------------------------------------|-------------------------------------|------------------------------------|  
| raw `[u8; 32]` access | 492.22 ps – 501.52 ps | baseline |  
| `Fixed<[u8; 32]>` + `.expose_secret()` | 476.92 ps – 487.12 ps | −3.0 % to −23.9 % |  
| `fixed_alias! (RawKey` explicit access | 475.07 ps – 482.91 ps | −3.4 % to −30.5 % |  

All implementations are statistically indistinguishable from raw arrays at the picosecond level.  
The explicit `.expose_secret()` path incurs **no measurable overhead**.  

[View full Criterion report](https://slurp9187.github.io/secure-gate/benches/fixed_vs_raw/report/)

## Changelog  
[CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)  

## License  
MIT OR Apache-2.0  

---
**v0.6.1 adds ergonomic RNG conversions and convenience methods while maintaining strict security guarantees.**  
All secret access is explicit. No silent leaks remain. **Security fix**: Removed `into_inner()` from `Fixed`/`Dynamic` types to enforce the security model. Use `expose_secret()` or `expose_secret_mut()` for all secret access.