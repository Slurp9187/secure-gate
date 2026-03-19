# Security Considerations for secure-gate

Last updated: 2026-03 (for v0.8.0-rc.1)

## TL;DR
- **No independent audit** — review the source code yourself before production use.
- **No unsafe code** — `#![forbid(unsafe_code)]` enforced unconditionally.
- **Explicit exposure only** — all secret access requires `.expose_secret()` / `.with_secret()` or mutable equivalents; no `Deref`, `AsRef`, or implicit borrowing.
- **Zeroization on drop** — full buffer (including spare capacity) always wiped on drop (inner type must implement `Zeroize`).
- **Timing-safe equality** — use `ConstantTimeEq` (`ct-eq`) or `ConstantTimeEqExt` / `ct_eq_auto` (`ct-eq-hash`); `==` is deliberately not implemented.
- **Opt-in risk** — cloning and serialization require explicit marker traits (`CloneableSecret`, `SerializableSecret`).
- **Vulnerability reporting** — preferred: GitHub private vulnerability reporting (Security tab); public issues acceptable.

This document outlines the security model, design choices, strengths, known limitations, and review guidance for `secure-gate`.

## Audit Status

`secure-gate` has **not** undergone an independent security audit.

The crate is intentionally small and relies on well-vetted dependencies:

- `zeroize` — memory wiping
- `subtle` — constant-time comparison primitives
- `blake3` — cryptographic hashing
- `rand_core` + `getrandom` — secure randomness
- Encoding crates (`hex`, `base64`, `bech32`) — battle-tested (supports bech32 / bech32m)

**Before production use**, review:

- Source code
- Tests (especially `tests/ct_eq_suite/` and `tests/proptest_suite/`)
- Dependency versions and their security history

## Core Security Model

| Property                          | Guarantee / Design Choice                                                                 |
|-----------------------------------|--------------------------------------------------------------------------------------------|
| Explicit exposure                 | Private inner fields; access only via audited methods (`expose_secret`, `with_secret`)   |
| Scoped exposure (preferred)       | Closures limit borrow lifetime; prevents long-lived references                             |
| Direct exposure (escape hatch)    | `expose_secret()` / `expose_secret_mut()` — grep-able, auditable                           |
| No implicit leaks                 | No `Deref`, `AsRef`, `Copy`, `Clone` (unless `cloneable` + marker)                         |
| Zeroization                       | Full allocation always wiped on drop; includes `Vec`/`String` spare capacity (inner type must implement `Zeroize`) |
| Timing safety                     | `ConstantTimeEq` (`.ct_eq()`) for typical small/fixed keys; `ConstantTimeEqExt` / `ct_eq_auto` for large or variable data; `ct_eq_hash` for uniform probabilistic checks. Avoid `==`. |
| Probabilistic equality (`ct-eq-hash`) | keyed BLAKE3 (when `rand` enabled) or unkeyed; collision risk ~2⁻²⁵⁶ either way (negligible for practical purposes) |
| Opt-in risky features             | Cloning/serialization gated by marker traits (`CloneableSecret`, `SerializableSecret`)         |
| Redacted debug                    | `Debug` impl always prints `[REDACTED]`                                                    |
| No unsafe code                    | `#![forbid(unsafe_code)]` enforced at crate level                                          |

## Feature Security Implications

| Feature              | Security Impact                                                                 | Recommendation                              |
|----------------------|----------------------------------------------------------------------------------|---------------------------------------------|
| `alloc` *(default)*  | Enables `Dynamic<T>` + full zeroization of `Vec`/`String` spare capacity. Use `default-features = false` for no-heap builds. | Enable unless on embedded/pure-stack target |
| `std`                | Full `std` support (implies `alloc`). Adds no additional security surface beyond `alloc`. | Optional; `alloc` is sufficient for most targets |
| `ct-eq`              | Timing-safe direct byte comparison                                               | Strongly recommended; avoid `==`            |
| `ct-eq-hash`         | Fast BLAKE3-based equality for large secrets; probabilistic but cryptographically safe | Prefer `ct_eq_auto` for most cases           |
| `rand`               | Secure random via `OsRng`; panics on failure                                     | Use only in trusted entropy environments    |
| `serde-deserialize`  | Direct binary deserialization (arrays/seqs only); no string auto-parsing. Binary-safe, no temporary buffers or ambiguous parsing. Eliminates format confusion attacks and auto-decoding vulnerabilities; forces explicit pre-deserialization decoding via format-specific traits. | Enable for trusted deserialization sources  |
| `serde-serialize`    | Opt-in export via marker trait; audit all implementations                        | Enable sparingly; monitor exfiltration risk |
| `encoding`           | Meta: enables all encoding sub-features (hex, base64url, bech32, bech32m); always requires `alloc` | Enable per-format instead for minimal surface |
| `encoding-hex`       | Hex encoding/decoding: `ToHex`, `FromHexStr`; requires `alloc`                   | Validate inputs upstream; prefer `try_from_hex` |
| `encoding-base64`    | Base64url encoding/decoding: `ToBase64Url`, `FromBase64UrlStr`; requires `alloc` | Validate inputs upstream; prefer `try_from_base64url` |
| `encoding-bech32`    | Bech32/BIP-173 encoding/decoding: `ToBech32`, `FromBech32Str`                    | Validate inputs upstream; test empty/invalid HRP |
| `encoding-bech32m`   | Bech32m/BIP-350 encoding/decoding: `ToBech32m`, `FromBech32mStr`                 | Validate inputs upstream; test empty/invalid HRP |
| `cloneable`          | Opt-in cloning via marker trait; increases exposure surface                      | Use minimally; prefer move semantics        |
| `full`               | All features enabled — convenient but increases attack surface                   | Development only; audit for production      |

## Module-by-Module Security Notes

> Security invariants (no `Deref`/`AsRef`, `Debug` prints `[REDACTED]`, zeroize on drop, opt-in clone/serialize) are documented in full on the [`Fixed`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html) and [`Dynamic`](https://docs.rs/secure-gate/latest/secure_gate/struct.Dynamic.html) rustdoc. This section focuses on weaknesses and mitigations not visible from the API surface.

### Wrappers (`dynamic.rs`, `fixed.rs`)

**Potential weaknesses**
- Long-lived `expose_secret()` references can defeat scoping
- Macro-generated aliases lack runtime size checks
- Certain error variants may indirectly leak length information (e.g. wrong decoded length).
  In most real-world usage (logging, API responses), length is already public metadata anyway (e.g. key length in JWT headers, signature length). Still, contextualize or redact errors when possible.

**Mitigations**
- Prefer `with_secret()` / `with_secret_mut()`
- Audit all `expose_secret()` calls
- Contextualize errors to avoid side-channel information

Zero-cost claim: performance indistinguishable from raw arrays; for detailed benchmarks, see [ZERO_COST_WRAPPERS.md](ZERO_COST_WRAPPERS.md).

### Traits (`traits/`)

**Potential weaknesses**
- Generic impls assume caller trustworthiness

**Mitigations**
- Audit every `CloneableSecret` / `SerializableSecret` impl — each is a deliberate security decision
- Validate inputs before trait usage

### Encoding/Decoding (Traits & Errors)

**Potential weaknesses**
- Decoding is inherently fallible; untrusted input may cause errors or temporary allocations
- Length/format hints in errors (e.g., invalid HRP)
- Bech32 edge cases: strict validation covers most, but test empty/invalid HRP/data to confirm no panics/leaks

**Mitigations**
- Treat all decoding input as untrusted; validate upstream
- Use specific traits (e.g., `FromBech32Str`) for strict format enforcement
- Fuzz parsers; sanitize inputs before decoding
- Decoding errors may include format hints — treat as potential metadata leaks in sensitive contexts; redact logs or use custom error display in production
- Audit custom `Cloneable`/`Serializable` impls to preserve zeroization

## Best Practices

- The `alloc` feature is enabled by default and provides `Dynamic<T>` with full zeroization; use `default-features = false` for embedded / pure-stack builds (`Fixed<T>` only)
- Prefer scoped `with_secret()` over long-lived `expose_secret()`
- For typical fixed-size secrets (keys, nonces, ≤ 64 bytes) prefer `.ct_eq()` for deterministic constant-time comparison; use `ct_eq_auto(…, None)` when sizes are variable or large. See [CT_EQ_AUTO.md](CT_EQ_AUTO.md) for crossover tuning guidance.
- Audit every `CloneableSecret` / `SerializableSecret` impl
- Validate and sanitize all inputs before encoding/decoding
- Use specific format traits (`FromBech32Str`, `FromHexStr`, …) when the expected format is known
- Probabilistic equality (`ct-eq-hash`): Negligible collision risk (~2⁻²⁵⁶), but use `ct_eq` for deterministic needs; bound input sizes to prevent DoS
- Monitor dependency CVEs and update regularly
- Treat secrets as radioactive — minimize exposure surface

## Vulnerability Reporting

- **Preferred**: GitHub private vulnerability reporting (Repository → Security → Report a vulnerability)
- **Alternative**: Public issue or draft
- **Expected response**: Acknowledgment within 48 hours; coordinated disclosure
- **Public disclosure**: After fix is released and users have reasonable time to update

## Disclaimer

This document reflects design intent and observed properties as of the current release.

**No warranties are provided**. Users are solely responsible for their own security evaluation, threat modeling, and audit.
