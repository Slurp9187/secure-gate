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
- **No unsafe code in crate itself** — `#![forbid(unsafe_code)]` enforced in minimal configurations.
- **Redacted Debug** — prevents accidental secret logging via `{:?}`.
- **No automatic Clone / Serialize** — requires explicit opt-in via macros + marker traits (`CloneableType`, `SerializableType`).

## Feature Security Implications

| Feature                  | Security Impact                                                                 | Recommendation                                      |
|--------------------------|---------------------------------------------------------------------------------|-----------------------------------------------------|
| `secure` (default)       | Enables `zeroize` + `ct-eq` — recommended baseline                              | Always enable unless constrained environments require otherwise |
| `zeroize`                | Zeroes memory on drop; required for safe cloning                                | Strongly recommended                                |
| `ct-eq`                  | Timing-safe comparisons via `subtle` crate                                      | Strongly recommended; avoid `==`                    |
| `hash-eq`                | Fast equality via BLAKE3 + ct-eq on digest; probabilistic constant-time         | Use only when performance matters; prefer `ct-eq` for small secrets |
| `cloneable`              | Opt-in cloning via macros + `CloneableType` marker; increases copies in memory  | Use only when multiple owners required              |
| `encoding`               | Explicit encoding; zeroizes invalid inputs when `zeroize` enabled               | Validate inputs upstream                            |
| `rand`                   | Generates cryptographically secure random values. Ensure System RNG is available and secure. | Ensure OS entropy source is secure                  |
| `serde-serialize`        | Opt-in serialization via `SerializableType` marker; risk of exfiltration        | Enable only when needed; audit all impls            |
| `serde-deserialize`      | Allows loading secrets; temporary copies during parsing                         | Enable only for trusted sources                     |

### Detailed Notes on `hash-eq` Feature
The `hash-eq` feature provides an alternative equality mechanism using BLAKE3 hashing followed by constant-time comparison of the 32-byte digest.

**Security Properties**
- **Very flat timing behavior** — Always hashes to a fixed 32-byte output → comparison time is independent of secret length/content (unlike linear `ct_eq` on large secrets).
- **Collision resistance** — BLAKE3-256 has ~2⁻¹²⁸ birthday bound → cryptographically negligible risk of false equality.
- **Side-channel resistance** — BLAKE3 is designed to be constant-time in core operations (parallel, table-free, no secret-dependent branches/loops). Digest comparison uses `ConstantTimeEq` (via `subtle`).
- **Deterministic & fast** — No per-comparison state or randomness → predictable and performant.

**Trade-offs & Risks**
- **Probabilistic constant-time** — Not strictly data-independent like byte-by-byte `ct_eq`. Theoretical possibility of distinguishing via extremely precise timing on collisions (astronomically unlikely).
- **Higher CPU cost for small secrets** — BLAKE3 overhead (~77 ns for 32 bytes) is comparable to direct `ct_eq` (~128 ns) in benchmarks — difference within noise.
- **Hash-flooding / DoS risk** — Attacker-controlled comparisons trigger full BLAKE3 → higher cost than direct `ct_eq`. Mitigate with rate limiting or bounded comparisons in exposed APIs.
- **No keyed hashing** — Pure BLAKE3 is deterministic. Deterministic hashing is fine for equality but vulnerable to preimage attacks in adversarial settings.

**When to use `hash-eq` vs `ct-eq`**
- Prefer `ct-eq` for small/fixed-size secrets (≤ 128 bytes) — strictly constant-time, minimal overhead.
- Prefer `hash-eq` for large/variable-length secrets (> ~200 bytes) — faster, flatter timing profile, enables `HashMap` usage.
- Never rely on `==` without `hash-eq` or `ct-eq` — timing leaks possible.

**Review Points for `hash-eq`**
- Confirm `ct-eq` feature is also enabled (required dependency).
- Audit usage in performance-sensitive or attacker-exposed code (e.g. HashMap keys).
- Test timing uniformity with high-resolution tools (cachegrind, custom benchmarks).
- Consider adding keyed BLAKE3 (per-process random key) in future if hash-flooding becomes realistic concern.
- Monitor BLAKE3 dependency for CVEs (currently low risk).

## Potential Concerns
- **Serde Serialization/Deserialization**: Deserialize from untrusted sources creates temporary copies; validate inputs and trust source. Serialize gated by `SerializableType` marker; audit all impls.
- **Heap Allocation**: `Dynamic<T>` types zeroize full capacity (including slack) on drop when `zeroize` enabled. Cannot guarantee previous reallocations did not leave values on heap.
- **Custom Types**: Avoid non-zeroizeable inner types; carefully implement `CloneableType` / `SerializableType`.
- **Error Handling**: Errors may leak length metadata; fields `pub(crate)` to limit exposure.
- **Macro Usage**: Macros create types without runtime checks — audit generated types.

## Best Practices
- Enable default `secure` feature unless extreme constraints.
- Audit all `.expose_secret()` / `.expose_secret_mut()` calls.
- Use semantic aliases via macros.
- Prefer non-cloneable / non-serializable types when possible.
- Validate encoding/decoding inputs.
- Regularly review dependencies for updates.

## Reporting Vulnerabilities
- Preferred: GitHub private vulnerability reporting (Security tab → Report a vulnerability).
- Alternative: Draft / public issue.
- Response target: 48 hours.
- Public disclosure welcome after coordinated fix.

## Disclaimer
This crate is provided under MIT OR Apache-2.0 licenses. It comes with no warranties. Users are responsible for evaluating security for their specific use cases.