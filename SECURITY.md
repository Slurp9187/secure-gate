# Security Considerations for secure-gate

## TL;DR

- **No independent audit** — review the source code yourself before production use.
- **No unsafe code** — `#![forbid(unsafe_code)]` enforced unconditionally.
- **Explicit exposure only** — all secret access requires `.expose_secret()` / `.with_secret()` or mutable equivalents; no `Deref`, `AsRef`, or implicit borrowing.
- **Zeroization on drop** — full buffer (including slack capacity) wiped when `zeroize` feature is enabled.
- **Timing-safe equality** — use `ConstantTimeEq` (`ct-eq`) or `HashEq` / `hash_eq_opt` (`hash-eq`); `==` is deliberately not implemented.
- **Opt-in risk** — cloning and serialization require explicit marker traits (`CloneableType`, `SerializableType`).
- **Vulnerability reporting** — preferred: GitHub private vulnerability reporting (Security tab); public issues acceptable.

This document outlines the security model, design choices, strengths, known limitations, and review guidance for `secure-gate`.

## Audit Status

`secure-gate` has **not** undergone an independent security audit.  
The crate is intentionally small and relies on well-vetted dependencies:

- `zeroize` — memory wiping
- `subtle` — constant-time comparison primitives
- `blake3` — cryptographic hashing
- `rand_core` + `getrandom` — secure randomness
- Encoding crates (`hex`, `base64`, `bech32`) — battle-tested

**Before production use**, review:

- Source code
- Tests (especially `hash_eq_tests.rs` and `proptest_tests.rs`)
- Dependency versions and their security history

## Core Security Model

| Property                          | Guarantee / Design Choice                                                                 |
|-----------------------------------|--------------------------------------------------------------------------------------------|
| Explicit exposure                 | Private inner fields; access only via audited methods (`expose_secret`, `with_secret`)   |
| Scoped exposure (preferred)       | Closures limit borrow lifetime; prevents long-lived references                             |
| Direct exposure (escape hatch)    | `expose_secret()` / `expose_secret_mut()` — grep-able, auditable                           |
| No implicit leaks                 | No `Deref`, `AsRef`, `Copy`, `Clone` (unless `cloneable` + marker)                         |
| Zeroization                       | Full allocation wiped on drop (`zeroize` feature); includes `Vec`/`String` slack capacity |
| Timing safety                     | `ConstantTimeEq` for direct comparison; `HashEq` / `hash_eq_opt` for large/variable data   |
| Probabilistic equality (`hash-eq`) | BLAKE3 + fixed 32-byte digest compare; collision risk ~2⁻¹²⁸ (negligible)                 |
| Opt-in risky features             | Cloning/serialization gated by marker traits (`CloneableType`, `SerializableType`)         |
| Redacted debug                    | `Debug` impl always prints `[REDACTED]`                                                    |
| No unsafe code                    | `#![forbid(unsafe_code)]` enforced at crate level                                          |

## Feature Security Implications

| Feature              | Security Impact                                                                 | Recommendation                              |
|----------------------|----------------------------------------------------------------------------------|---------------------------------------------|
| `secure` (default)   | Enables `zeroize` + `ct-eq` — secure-by-default baseline                         | Always enable unless extreme constraints    |
| `zeroize`            | Wipes memory on drop; enables safe opt-in cloning/serialization                  | Strongly recommended                        |
| `ct-eq`              | Timing-safe direct byte comparison                                               | Strongly recommended; avoid `==`            |
| `hash-eq`            | Fast BLAKE3-based equality for large secrets; probabilistic but cryptographically safe | Use `hash_eq_opt` for most cases            |
| `rand`               | Secure random via `OsRng`; panics on failure                                     | Use only in trusted entropy environments    |
| `serde-deserialize`  | Auto-decodes hex/base64/bech32; temporary buffers zeroized on failure            | Enable only for trusted input sources       |
| `serde-serialize`    | Opt-in export via marker trait; audit all implementations                        | Enable sparingly; monitor exfiltration risk |
| `encoding-*`         | Explicit encoding/decoding; fallible; zeroizes invalid inputs                    | Validate inputs upstream                    |
| `cloneable`          | Opt-in cloning via marker trait; increases exposure surface                      | Use minimally; prefer move semantics        |
| `full`               | All features enabled — convenient but increases attack surface                   | Development only; audit for production      |

## Module-by-Module Security Notes

### Wrappers (`dynamic.rs`, `fixed.rs`)

**Strengths**
- Private `inner` field prevents direct access
- Dual exposure model: scoped closures (leak-resistant) + direct refs (auditable)
- Full-capacity zeroization (`zeroize`)
- Redacted `Debug` output

**Potential weaknesses**
- Long-lived `expose_secret()` references can defeat scoping
- Macro-generated aliases lack runtime size checks
- Error messages may leak length metadata

**Mitigations**
- Prefer `with_secret()` / `with_secret_mut()`
- Audit all `expose_secret()` calls
- Contextualize errors to avoid side-channel information

### Traits (`traits/`)

**Strengths**
- Marker traits (`CloneableType`, `SerializableType`) force deliberate opt-in
- `ConstantTimeEq` and `HashEq` provide safe equality alternatives

**Potential weaknesses**
- Generic impls assume caller trustworthiness

**Mitigations**
- Audit custom marker impls
- Validate inputs before trait usage

### Encoding & Errors

**Strengths**
- Explicit methods; typed errors; fallible operations
- Bech32 HRP validation prevents injection

**Potential weaknesses**
- Temporary allocations during decoding
- Length/format hints in errors

**Mitigations**
- Fuzz parsers; upstream input validation

## Best Practices

- Enable `secure` feature unless you have extreme constraints
- Prefer scoped `with_secret()` over long-lived `expose_secret()`
- Use `hash_eq_opt(…, None)` for general-purpose equality checks
- Audit every `CloneableType` / `SerializableType` impl
- Validate and sanitize all inputs before encoding/decoding
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

Thank you for reviewing `secure-gate` carefully.
