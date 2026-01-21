# Security Considerations for secure-gate

## TL;DR
- No independent security audit yet—review the code yourself before production use.
- Default feature is `secure` (`zeroize` + `ct-eq` enabled).
- Explicit `.expose_secret()` and `.expose_secret_mut()` for auditability; zeroization on drop (with `zeroize`).
- Use GitHub's Security tab for vulnerability reports (private preferred, public acceptable).

This document outlines key security aspects to consider when using the `secure-gate` crate for handling sensitive data. It is intended for developers evaluating the library for security-critical applications.

## Audit Status
`secure-gate` has not undergone independent security audit. The crate is in active development and relies on well-established dependencies (e.g., `zeroize`, `subtle`). Review the implementation and test coverage before use in production.

## Core Security Model
- **Explicit Exposure**: Secret data access requires explicit `.expose_secret()` and `.expose_secret_mut()` calls, minimizing accidental leaks. Audit all `.expose_secret()` and `.expose_secret_mut()` calls in your code.
- **Zeroization**: Memory is zeroized on drop when `zeroize` feature is enabled. Without it, data may linger until normal deallocation.
- **No Implicit Access**: No `Deref` implementations prevent silent borrowing or copying.
- **Constant-Time Operations**: Timing-safe equality available with `ct-eq` feature; disable only with justification.
- **No Unsafe Code**: The crate contains no `unsafe` code. `forbid(unsafe_code)` is applied in minimal configurations as a defensive measure.

## Feature Implications

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
- **Very flat timing behavior**: Always hashes to a fixed 32-byte output → comparison time is independent of secret length/content (unlike linear `ct_eq` on large secrets).
- **Collision resistance**: BLAKE3-256 has ~2⁻¹²⁸ birthday bound → cryptographically negligible risk of false equality.
- **Side-channel resistance**: BLAKE3 is designed to be constant-time in core operations (parallel, table-free, no secret-dependent branches/loops). Digest comparison uses `ConstantTimeEq` (via `subtle`).
- **Deterministic & fast**: No per-comparison state or randomness → predictable and performant.

**Trade-offs & Risks**
- **Probabilistic constant-time**: Not strictly data-independent like byte-by-byte `ct_eq`. Theoretical possibility of distinguishing via extremely precise timing on collisions (astronomically unlikely).
- **Higher CPU cost for small secrets**: BLAKE3 overhead (~100–500 cycles) exceeds direct `ct_eq` for N ≤ ~64 bytes.
- **Hash-flooding / DoS risk**: Attacker-controlled comparisons trigger full BLAKE3 → higher cost than direct `ct_eq`. Mitigate with rate limiting or bounded comparisons in exposed APIs.
- **No keyed hashing**: Pure BLAKE3 is deterministic. Deterministic hashing is fine for equality but vulnerable to preimage attacks in adversarial settings.

**When to use `hash-eq` vs `ct-eq`**
- Prefer `ct-eq` for small/fixed-size secrets (≤ 128 bytes) — strictly constant-time, minimal overhead.
- Prefer `hash-eq` for large/variable-length secrets (> ~200 bytes) — dramatically faster, flatter timing profile, enables `HashMap` usage.
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