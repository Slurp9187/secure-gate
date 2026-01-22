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
- **Constant-time equality** — available via `ct-eq` feature; `==` discouraged.
- **No automatic Clone / Serialize** — requires explicit opt-in via macros + marker traits (`CloneableType`, `SerializableType`).

<<<<<<< Updated upstream
## Feature Implications
- **`zeroize` (included in default `secure`)**: Enables memory wiping and safe cloning. Recommended for all use cases handling secrets.
- **`ct-eq` (included in default `secure`)**: Provides timing-safe comparisons. Avoid `==` for secrets.
- **`rand`**: Generates cryptographically secure random values. Ensure System RNG is available and secure.
- **Encoding Features**: Validate inputs before encoding to prevent malformed outputs or attacks.

## Potential Concerns
- **Serde Serialization/Deserialization**: With `serde-deserialize` feature enabled, `Deserialize` allows loading secrets from potentially untrusted sources—validate inputs and trust the source. With `serde-serialize` feature enabled, `Serialize` is uniformly gated by `SerializableType` marker to prevent accidental exfiltration; audit all `impl SerializableType` in your codebase.
- **Heap Allocation**: `Dynamic<T>` types zeroize the full backing buffer capacity (including slack) on drop when the `zeroize` feature is enabled:  
  - For `Vec<T>`: "Best effort" zeroization for Vec. Ensures the entire capacity of the Vec is zeroed. Cannot ensure that previous reallocations did not leave values on the heap. ([docs](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html#impl-Zeroize-for-Vec%3CZ%3E))  
  - For `String`: "Best effort" zeroization for String. Clears the entire capacity of the String. Cannot ensure that previous reallocations did not leave values on the heap. ([docs](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html#impl-Zeroize-for-String))
- **Custom Types**: Avoid wrapping sensitive data in non-zeroizeable types; implement `CloneableType` carefully.
- **Error Handling**: Errors like `FromSliceError` expose length metadata (e.g., expected vs. actual), which may be sensitive in some contexts; fields are `pub(crate)` to prevent direct external access while allowing internal debugging. Invalid inputs are zeroized in encoding failures (with `zeroize` enabled).
- **Macro Usage**: Macros create type aliases without runtime checks—ensure they match your security needs.
=======
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
>>>>>>> Stashed changes

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
<<<<<<< Updated upstream
- Enable the default `secure` feature (`zeroize` + `ct-eq`) unless constrained environments require otherwise.
- Audit all `.expose_secret()` and `.expose_secret_mut()` calls for necessity and duration.
- Use semantic aliases (e.g., `fixed_alias!`) for clarity.
- Prefer `CloneableArray` etc. over custom `CloneableType` impls.
- Validate encoding inputs and handle errors securely.
- Regularly review dependencies for updates.

## Reporting Vulnerabilities
- Preferred: Use GitHub's private vulnerability reporting (Security tab → Report a vulnerability).
- Alternative: Open a draft issue or public issue (if non-exploitable).
- Public disclosure is welcome after a fix, but private first helps protect users.
- Response target: 48 hours.

## Module-by-Module Security Analysis
This section provides a professional reviewer's perspective on each module's security design, highlighting strengths, potential weaknesses, and review points. It assumes a threat model focused on confidentiality, integrity, and timing attacks in cryptographic contexts.

### Core Modules (`lib.rs`, `fixed.rs`, `dynamic.rs`)
**Strengths**:
- Explicit exposure model forces audited access—strong against accidental leaks.
- Zeroization on drop (with `zeroize`) prevents lingering secrets.
- Type safety prevents Deref/AsRef misuse.

**Potential Weaknesses**:
- Macro expansions create aliases without runtime checks—audit generated types for unintended usage.
- Error types (`FromSliceError`) leak length metadata; ensure not sensitive in context.

**Mitigations**:
- Use compile-time assertions in macros to catch invalid sizes early.
- Contextualize error handling to avoid leaking metadata in sensitive contexts.

**Review Points**:
- Audit all `.expose_secret()` and `.expose_secret_mut()` calls in your code.
- Check for heap overuse in `Dynamic` variants; monitor for side-channel leaks via allocation patterns.
- Ensure feature-gated impls (e.g., `Clone`) are not accidentally enabled.

### Cloneable Module (`cloneable/`)
**Strengths**:
- Opt-in cloning with `CloneableType` marker—prevents bypass of zeroization.
- Pre-built types (`CloneableArray`, etc.) implement best practices automatically.
- Entire module gated behind `zeroize` feature—cloning unavailable without zeroization.

**Potential Weaknesses**:
- Cloning multiplies exposure surface—review necessity and lifecycle.
- Custom `CloneableType` impls require careful bounds satisfaction (must implement both `Clone` and `Zeroize`—enforced by trait).

**Mitigations**:
- Prefer pre-baked types; use custom impls only when necessary.
- Limit cloning to essential operations; use move semantics where possible.
- Zeroize cloned copies promptly to minimize exposure window.
- Validate serde inputs and handle errors securely; only deserialize from trusted sources (requires `serde-deserialize`).
- Explicitly impl `SerializableType` only for types that must be serialized; grep for impls in audits (requires `serde-serialize`).

**Review Points**:
- Confirm `zeroize` feature is enabled if cloning is used.
- Audit clone usage for unintended duplications.
- Verify custom types satisfy `Zeroize` (compiler-enforced).

### Random Module (`random/`)
**Strengths**:
- Enforces RNG construction—cannot create from arbitrary bytes.
- Ties to System RNG (`OsRng`) for freshness and entropy.

**Potential Weaknesses**:
- Falls back to panics on RNG failure—may deny service; handle `try_generate()` errors.
- Depends on System RNG security—attackable via OS compromise.
- Allocation size leakage via `Vec<u8>` resizing.

**Mitigations**:
- Prefer `try_generate()` and handle errors gracefully (e.g., retry or fallback mechanisms).
- Deploy in trusted OS environments; monitor for RNG entropy exhaustion.
- Pre-allocate buffers or use fixed-size types to avoid size leaks.

**Review Points**:
- Test RNG failure scenarios; handle errors gracefully.
- Verify entropy source in deployment environment.
- Review encoding integrations for post-generation leaks.

### Constant-Time Equality (`traits/constant_time_eq.rs`)
**Strengths**:
- Provides `ConstantTimeEq` trait—prevents timing leaks in comparisons.
- Uses `subtle` crate for vetted impls.

**Potential Weaknesses**:
- Fallback to regular `==` without feature—timing vulnerable; ensure feature is enabled.

**Mitigations**:
- Always enable `ct-eq` feature for sensitive comparisons; prohibit regular `==` in code reviews.
- Wrap comparisons in higher-level APIs that enforce constant-time behavior.

**Review Points**:
- Confirm `ct-eq` feature usage; audit for plaintext comparisons.
- Test timing differences with tools like cachegrind.

### Encoding Module (`encoding/`)
**Strengths**:
- Validates inputs (e.g., hex/base64)—prevents injection or malformed data.
- Zeroizes invalid inputs with `zeroize`.
- Supports multiple formats with error handling.

**Potential Weaknesses**:
- Bech32 HRP validation relies on `bech32` crate—review for edge cases.
- Encoding errors may leak input lengths/metadata.
- Decoding allocates new buffers—potential for temporary exposure.

**Mitigations**:
- Fuzz test `bech32` parsing with invalid HRPs; validate inputs upstream.
- Sanitize error messages to avoid leaking lengths; handle errors without exposing details.
- Use stack-allocated decoding where possible or immediately zeroize temporary buffers.

**Review Points**:
- Validate all encoding inputs upfront; fuzz test parsers.
- Monitor for encoding format attacks (e.g., oversized inputs).
- Ensure decoded outputs are handled securely post-validation.

### Error Handling (`error.rs`)
**Strengths**:
- Exposes only safe metadata (e.g., lengths); zeroizes secrets on failure.

**Potential Weaknesses**:
- Length metadata (e.g., expected vs. actual) may be sensitive in some contexts. Fields are `pub(crate)` to prevent direct external access while allowing internal debugging.

**Mitigations**:
- The `Display` impl provides informative messages without exposing raw fields.
- In highly sensitive contexts, wrap or genericize errors further.

**Review Points**:
- Audit error messages for unintended info disclosure.
- Ensure error handling doesn't bypass zeroization.

### Serde Features (`serde-deserialize`, `serde-serialize` features across modules)
**Strengths**:
- `Deserialize` (via `serde-deserialize`) uses secure construction patterns (e.g., `try_init_with` for cloneables) with zeroizing of invalid inputs.
- **Serialize** (via `serde-serialize`) is uniformly gated by `SerializableType` marker with no blanket impls prevents accidental exfiltration—fully grep-able and auditable.
- Matches `secrecy` crate's approach for high-risk operations like serialization.

**Potential Weaknesses**:
- `Deserialize` (via `serde-deserialize`) allows loading from potentially untrusted sources—assumes trusted input; no runtime format validation beyond serde.
- Dependency on `serde` ecosystem increases attack surface; vulnerabilities in serde could affect secret handling.
- Encoding types serialize as strings, which are plaintext—leakage if not handled carefully post-serialization (requires `serde-serialize`).
- Temporary exposure during deserialization before wrapping (mitigated by immediate construction/zeroizing).

**Mitigations**:
- Only deserialize from verified, trusted sources; validate inputs upstream.
- Pin `serde` versions and monitor for CVEs; use minimal serde features.
- Zeroize serialized outputs immediately; avoid network transmission.
- Test with malicious inputs; ensure invalid data is zeroized (requires `zeroize`).

**Review Points**:
- Audit all `impl SerializableType` for necessity; prefer not to serialize secrets (enable `serde-serialize` only when required).
- Confirm `zeroize` is enabled for secure handling of invalid deserialization inputs (enable `serde-deserialize` only for loading trusted configs).
- Test serde roundtrips with edge cases (malformed JSON, oversized inputs).
- Verify deserialization sources are trusted; handle errors securely.

### Overall Architecture
**Strengths**:
- Modular, feature-gated design—reduces attack surface when unused.
- No-unsafe-by-default with selective allowances—code review friendly.
- Comprehensive tests (doctests pass)—covers edge cases.

**Potential Weaknesses**:
- Dependency chain (`zeroize`, `subtle`, `rand`, etc.)—vulns propagate; keep updated.
- Allocation patterns may leak via side-channels—review in high-security apps.
- Macros expand at compile-time—harder to audit; verify expansions.

**Mitigations**:
- Enable dependency security alerts (e.g., GitHub Dependabot); pin versions conservatively.
- Use constant-time allocators or custom allocators in sensitive contexts to hide patterns.
- Expand macros manually for review (e.g., via `cargo expand`); test expanded code.

**General Review Advice**:
- Run static analysis (clippy) and fuzz testing on custom usage.
- Monitor heap usage and timing with profilers.
- For production, isolate sensitive operations and consider HSMs or enclaves.

This analysis is not exhaustive—perform your own threat modeling.
=======
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
>>>>>>> Stashed changes

## Disclaimer
This document reflects design intent and observed properties as of January 2026.  
No warranties are provided. Users are responsible for their own security evaluation.