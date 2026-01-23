# Security Considerations for secure-gate

## TL;DR
- **No independent security audit** — review the code yourself before production use.
- **Default feature set**: `secure` meta-feature (`zeroize` + `ct-eq` enabled for secure-by-default).
- **Explicit exposure required**: Scoped `with_secret()`/`with_secret_mut()` (recommended) or direct `expose_secret()`/`expose_secret_mut()` calls for all access — zero-cost, fully elided by optimizer.
- **Memory zeroization**: On drop (including spare capacity in `Vec`/`String`) when `zeroize` feature is enabled.
- **Opt-in behaviors**: Cloning/serialization require marker traits (`CloneableType`/`SerializableType`) — no implicit risks.
- **No unsafe code**: Unconditionally forbidden (`#![forbid(unsafe_code)]`).
- **Vulnerability reporting**: Use GitHub Security tab (private preferred, public acceptable).

This document summarizes security-relevant design choices, strengths, potential weaknesses, and review points for the `secure-gate` crate. It is intended for developers performing threat modeling or security reviews.

## Audit Status
`secure-gate` has **not** undergone independent security audit.  
The implementation relies on vetted dependencies (`zeroize`, `subtle`, `blake3`, `rand`, encoding crates like `bech32`, `hex`, `base64`).  
**Review source code, tests, and dependencies** before using in security-critical applications.

## Core Security Model
- **Explicit exposure only** — Scoped `with_secret()`/`with_secret_mut()` (prevents leaks via closures) or direct `expose_secret()`/`expose_secret_mut()` (auditable escape hatches); no `Deref`, `AsRef`, or implicit borrowing paths.
- **Zeroization on drop** — Enabled via `zeroize` feature; wipes full backing buffer (including slack capacity in `Vec`/`String`).
- **No unsafe code** — `#![forbid(unsafe_code)]` enforced unconditionally across all builds.
- **Redacted Debug** — Prevents accidental secret leakage via `{:?}` formatting.
- **Timing-safe equality** — `ConstantTimeEq` trait (via `ct-eq` feature) for byte-level comparisons; `HashEq` for large/variable secrets; `==` not supported (use timing-safe alternatives).
- **Opt-in risky behaviors** — Cloning/serialization require marker traits (`CloneableType`/`SerializableType`); no automatic exposure.
- **Marker-based security** — Traits like `CloneableType` ensure deliberate opt-in, reducing accidental risks.
- **Encoding with validation** — Explicit methods; zeroizes invalid inputs; fallible Bech32 with HRP checks.

## Feature Security Implications

| Feature             | Security Impact                                                                 | Recommendation                                      |
|---------------------|---------------------------------------------------------------------------------|-----------------------------------------------------|
| `secure` (default)  | Meta-feature enabling `zeroize` + `ct-eq` — baseline for safety                 | Always enable unless extreme constraints            |
| `zeroize`           | Zeroes memory on drop; enables safe opt-in behaviors                           | Strongly recommended                                |
| `ct-eq`             | `ConstantTimeEq` trait for timing-safe comparisons                              | Strongly recommended; avoid `==`                    |
| `hash-eq`           | `HashEq` trait: BLAKE3 hashing + ct-eq on digest; probabilistic safety for large data | Use for performance on large secrets; prefer `ct-eq` for small |
| `rand`              | `OsRng` for secure randomness; `from_random()` methods                          | Ensure OS entropy is secure; panics handled         |
| `serde`             | Meta-feature enabling both `serde-deserialize` and `serde-serialize`           | Enable only when serializing secrets is necessary   |
| `serde-deserialize` | Load secrets from strings; temporary buffers zeroized on failure               | Enable only for trusted sources                     |
| `serde-serialize`   | Opt-in export via `SerializableType` marker; audit all impls                   | Enable sparingly; monitor for exfiltration          |
| `encoding`          | Meta-feature enabling all `encoding-*` features                                | Validate inputs upstream                            |
| `encoding-hex`      | Hex encoding/decoding; fallible; zeroizes invalids                             | Validate inputs upstream                            |
| `encoding-base64`   | Base64 encoding/decoding; fallible; zeroizes invalids                          | Validate inputs upstream                            |
| `encoding-bech32`   | Bech32/Bech32m with HRP validation; fallible                                    | Use for BIP173-compliant strings                    |
| `cloneable`         | `CloneableType` marker for duplication; increases exposure                      | Use minimally; prefer move semantics               |
| `full`              | Meta-feature enabling all features for complete functionality                   | Use for development; audit for production           |
| `insecure`          | Disables `zeroize` and `ct-eq` for testing/low-resource; strongly discouraged   | Never use in production                             |

## Module-by-Module Security Notes

### Core Wrappers (`fixed.rs`, `dynamic.rs`)
- **Strengths**
  - Private `inner` fields prevent direct access; all exposure via audited methods.
  - Dual exposure: Scoped `with_secret()` closures limit borrow lifetimes; direct `expose_secret()` is grep-able.
  - No `Deref`/`AsRef` prevents silent conversions or implicit borrowing.
  - Zeroization (via `zeroize`) wipes full capacity on drop.
- **Weaknesses**
  - User code can call `expose_secret()` and hold long-lived refs (defeating scoping).
  - Macro-generated aliases lack runtime checks—audit generated types.
  - Errors may leak length metadata (e.g., expected vs. actual sizes).
- **Mitigations**
  - Audit all `expose_secret()` calls; prefer `with_secret()`.
  - Use compile-time assertions in macros.
  - Contextualize error handling to avoid side-channel leaks.

### Polymorphic Traits (`traits/`)
- **Strengths**
  - `ExposeSecret`/`ExposeSecretMut`: Generic, zero-cost access with metadata.
  - Marker traits (`CloneableType`, `SerializableType`): Force opt-in for risky ops.
  - `ConstantTimeEq`/`HashEq`: Safe equality options.
- **Weaknesses**
  - Generic impls assume input trustworthiness.
- **Mitigations**
  - Audit custom marker impls; validate inputs.

### Encoding & Errors (`traits/secure_encoding.rs`, `error.rs`)
- **Strengths**
  - `SecureEncoding`: Explicit, type-safe encoding/decoding.
  - Errors (`Bech32Error`, `DecodingError`): Typed, minimal metadata; fallible ops prevent panics.
  - Bech32 with HRP validation prevents injection attacks.
- **Weaknesses**
  - Decoding allocates temps; invalid inputs zeroized but may reveal format attempts.
  - Lengths in errors could be sensitive.
- **Mitigations**
  - Upstream input validation; fuzz tests.
  - Wrap errors in sensitive contexts.

### Other Modules
- **Dependencies**: Rely on audited crates (`zeroize`, `subtle`, etc.); monitor for CVEs.
- **Random Generation**: `OsRng` panics on failure—mitigate with trusted environments.
- **Serde**: Opt-in deserialize from trusted sources; audit serialize impls.

## Best Practices
- **Enable defaults**: Use `secure` meta-feature unless constraints prohibit it.
- **Audit exposure**: Grep all `with_secret()`, `expose_secret()`, `expose_secret_mut()` calls—prefer scoped access.
- **Use aliases**: Leverage `fixed_alias!`, `dynamic_alias!` for semantic types.
- **Limit risky ops**: Avoid cloning/serialization unless necessary; audit all marker impls.
- **Input validation**: Check upstream before encoding/decoding; trust no inputs.
- **Monitor deps**: Keep dependencies updated; review CVE reports.
- **Code review**: Treat secrets like radioactive—explicit, minimal exposure.
- **Testing**: Run with all features; use fuzzing for parsers.

## Vulnerability Reporting
- **Preferred**: GitHub private vulnerability reporting (Security tab → Report a vulnerability).
- **Alternative**: Draft or public issue.
- **Response target**: 48 hours.
- **Disclosure**: Public after coordinated fix.

## Disclaimer
This document reflects design intent and observed properties as of January 2026.  
**No warranties provided**. Users are responsible for their own security evaluation and audit.