# Security Considerations for secure-gate

## TL;DR
- No independent security audit has been performed — review the code yourself before production use.
- Default feature set is `secure` (`zeroize` + `ct-eq` enabled).
- Explicit `.expose_secret()` / `.expose_secret_mut()` calls required for all access — zero-cost reborrows, fully elided by optimizer.
- Memory zeroed on drop (including spare capacity in `Vec`/`String`) when `zeroize` feature is enabled.
- Use GitHub Security tab for vulnerability reports (private reporting preferred, public acceptable).

This document summarizes security-relevant design choices, strengths, potential weaknesses, and review points for the `secure-gate` crate. It is intended for developers performing threat modeling or security reviews.

## Audit Status
`secure-gate` has **not** undergone independent security audit.  
The implementation relies on established dependencies (`zeroize`, `subtle`, `blake3`, `rand`, encoding crates).  
Users should review source code and test coverage before using in security-critical applications.

## Core Security Model
- **Explicit exposure only** — `.expose_secret()` / `.expose_secret_mut()` required; no `Deref`, `AsRef`, or implicit paths.
- **Zeroization on drop** — enabled via `zeroize` feature; full backing buffer (including slack capacity) is zeroized.
- **No unsafe code in crate itself** — `#![forbid(unsafe_code)]` enforced unconditionally.
- **Redacted Debug** — prevents accidental secret logging via `{:?}`.
- **Constant-time equality** — available via `ct-eq` feature; `==` discouraged.
- **No automatic Clone / Serialize** — requires explicit opt-in via macros + marker traits (`CloneableType`, `SerializableType`).

## Feature Security Implications

| Feature                  | Security Impact                                                                 | Recommendation                                      |
|--------------------------|---------------------------------------------------------------------------------|-----------------------------------------------------|
| `secure` (default)       | Enables `zeroize` + `ct-eq` — recommended baseline                              | Always enable unless extreme constraints            |
| `zeroize`                | Zeroes memory on drop; required for safe cloning                                | Strongly recommended                                |
| `ct-eq`                  | Timing-safe comparisons via `subtle` crate                                      | Strongly recommended; avoid `==`                    |
| `hash-eq`                | Fast equality via BLAKE3 + ct-eq on digest; probabilistic constant-time         | Use only when performance matters; prefer `ct-eq` for small secrets |
| `cloneable`              | Opt-in cloning via macros + `CloneableType` marker; increases copies in memory  | Use only when multiple owners required              |
| `serde-serialize`        | Opt-in serialization via `SerializableType` marker; risk of exfiltration        | Enable only when needed; audit all impls            |
| `serde-deserialize`      | Allows loading secrets; temporary copies during parsing                         | Enable only for trusted sources                     |
| `encoding-*`             | Explicit encoding; zeroizes invalid inputs when `zeroize` enabled               | Validate inputs upstream                            |
| `rand`                   | Uses `OsRng` for cryptographically secure randomness; panics on failure        | Ensure OS entropy source is secure                  |

## Module-by-Module Security Notes

### Core (`lib.rs`, `fixed.rs`, `dynamic.rs`)
- Strengths
  - Explicit exposure model forces audited access
  - No `Deref` / `AsRef` prevents silent leaks
  - Zeroization covers full capacity (including slack) when enabled
- Weaknesses
  - Macro expansions create aliases without runtime checks — audit generated types
  - Error types may leak length metadata (fields `pub(crate)` to limit exposure)
- Mitigations
  - Use compile-time size assertions in macros
  - Contextualize error handling to avoid metadata leaks

### Cloneable Module
- Strengths
  - Opt-in via macro + `CloneableType` marker
  - Gated behind `zeroize` — cloning unavailable without zeroization
- Weaknesses
  - Cloning multiplies exposure surface
- Mitigations
  - Prefer move semantics; limit cloning
  - Zeroize clones promptly
  - Audit custom `CloneableType` impls

### Serializable Module
- Strengths
  - Opt-in via macro + `SerializableType` marker
  - Serialize gated separately from deserialize
- Weaknesses
  - Serialization risk of leakage (logs, insecure storage)
  - Deserialize from untrusted sources creates temporary copies
- Mitigations
  - Enable `serde-serialize` only when required
  - Audit all `impl SerializableType`
  - Deserialize only from trusted sources
  - Zeroize invalid deserialization inputs

### Random Module
- Strengths
  - Uses `OsRng` for system CSPRNG
- Weaknesses
  - Panics on RNG failure (DoS vector)
  - Allocation size may leak via side-channels
- Mitigations
  - Use `try_from_random` variant when available
  - Deploy in trusted OS environments

### Constant-Time Equality
- Strengths
  - Delegates to `subtle` crate (vetted implementation)
- Weaknesses
  - Disabled without `ct-eq` feature → timing vulnerable
- Mitigations
  - Always enable `ct-eq` for sensitive comparisons

### Encoding Module
- Strengths
  - Explicit encoding; zeroizes invalid inputs
- Weaknesses
  - Decoding allocates temporary buffers
  - Bech32 HRP validation relies on upstream crate
- Mitigations
  - Validate inputs upstream
  - Fuzz test parsers

### Error Handling
- Strengths
  - Minimal metadata exposure
- Weaknesses
  - Length info in errors may be sensitive
- Mitigations
  - Wrap errors in high-sensitivity contexts

## Best Practices
- Enable default `secure` feature unless extreme constraints.
- Audit all `.expose_secret()` / `.expose_secret_mut()` calls.
- Use semantic aliases via macros.
- Prefer non-cloneable / non-serializable types when possible.
- Validate encoding/decoding inputs.
- Monitor dependencies for updates and CVEs.

## Vulnerability Reporting
- Preferred: GitHub private vulnerability reporting (Security tab → Report a vulnerability)
- Alternative: Draft / public issue
- Response target: 48 hours
- Public disclosure welcome after coordinated fix

## Disclaimer
This document reflects design intent and observed properties as of January 2026.  
No warranties are provided. Users are responsible for their own security evaluation.