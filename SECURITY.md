# Security Considerations for secure-gate

## TL;DR
- No independent audit yet—review the code yourself before production use.
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


## Best Practices
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

## Disclaimer
This crate is provided under MIT OR Apache-2.0 licenses. It comes with no warranties. Users are responsible for evaluating security for their specific use cases.
