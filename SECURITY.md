# Security Considerations for secure-gate

## TL;DR
- No independent audit yet—review the code yourself before production use.
- Defaults are secure (`zeroize` + `ct-eq` enabled).
- Explicit `.expose_secret()` for auditability; zeroization on drop (with `zeroize`).
- Use GitHub's Security tab for vulnerability reports (private preferred, public acceptable).

This document outlines key security aspects to consider when using the `secure-gate` crate for handling sensitive data. It is intended for developers evaluating the library for security-critical applications.

## Audit Status
`secure-gate` has not undergone independent security audit. The crate is in active development and relies on well-established dependencies (e.g., `zeroize`, `subtle`). Review the implementation and test coverage before use in production.

## Core Security Model
- **Explicit Exposure**: Secret data access requires explicit `.expose_secret()` calls, minimizing accidental leaks. Audit these calls in your code.
- **Zeroization**: Memory is zeroized on drop when `zeroize` feature is enabled. Without it, data may linger until normal deallocation.
- **No Implicit Access**: No `Deref` implementations prevent silent borrowing or copying.
- **Constant-Time Operations**: Timing-safe equality available with `ct-eq` feature; disable only with justification.

## Feature Implications
- **`zeroize` (Default)**: Enables memory wiping and safe cloning. Recommended for all use cases handling secrets.
- **`ct-eq` (Default)**: Provides timing-safe comparisons. Avoid `==` for secrets.
- **`rand`**: Generates cryptographically secure random values. Ensure OS RNG is available and secure.
- **Encoding Features**: Validate inputs before encoding to prevent malformed outputs or attacks.

## Potential Concerns
- **Unsafe Code**: The crate contains no `unsafe` code. `forbid(unsafe_code)` is applied in minimal configurations as a defensive measure.
- **Heap Allocation**: `Dynamic<T>` types may leave slack capacity until drop; call `shrink_to_fit()` to mitigate.
- **Custom Types**: Avoid wrapping sensitive data in non-zeroizeable types; implement `CloneSafe` carefully.
- **Error Handling**: Errors like `FromSliceError` expose length metadata only; in encoding failures, invalid inputs are zeroized (with `zeroize` enabled).
- **Macro Usage**: Macros create type aliases—ensure they match your security needs.

## Best Practices
- Enable default features (`zeroize` + `ct-eq`) unless constrained environments require otherwise.
- Audit `.expose_secret()` sites for necessity and duration.
- Use semantic aliases (e.g., `fixed_alias!`) for clarity.
- Prefer `CloneableArray` etc. over custom `CloneSafe` impls.
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
- Heap slack in `Dynamic<T>` (e.g., `Vec` capacity) not wiped until drop—call `shrink_to_fit()`; review for temporary allocations.
- Macro expansions create aliases without runtime checks—audit generated types for unintended usage.
- Error types (`FromSliceError`) leak length metadata; ensure not sensitive in context.

**Mitigations**:
- Regularly call `shrink_to_fit()` on `Dynamic` variants after operations to minimize slack.
- Use compile-time assertions in macros to catch invalid sizes early.
- Contextualize error handling to avoid leaking metadata in sensitive contexts.

**Review Points**:
- Verify all `.expose_secret()` calls in application code.
- Check for heap overuse in `Dynamic` variants; monitor for side-channel leaks via allocation patterns.
- Ensure feature-gated impls (e.g., `Clone`) are not accidentally enabled.

### Cloneable Module (`cloneable/`)
**Strengths**:
- Opt-in cloning with `CloneSafe` marker—prevents bypass of zeroization.
- Pre-built types (`CloneableArray`, etc.) implement best practices automatically.
- Entire module gated behind `zeroize` feature—cloning unavailable without zeroization.

**Potential Weaknesses**:
- Cloning multiplies exposure surface—review necessity and lifecycle.
- Custom `CloneSafe` impls require careful bounds satisfaction (must implement both `Clone` and `Zeroize`—enforced by trait).

**Mitigations**:
- Prefer pre-baked types; use custom impls only when necessary.
- Limit cloning to essential operations; use move semantics where possible.
- Zeroize cloned copies promptly to minimize exposure window.

**Review Points**:
- Confirm `zeroize` feature is enabled if cloning is used.
- Audit clone usage for unintended duplications.
- Verify custom types satisfy `Zeroize` (compiler-enforced).

### Random Module (`random/`)
**Strengths**:
- Enforces RNG construction—cannot create from arbitrary bytes.
- Ties to OS RNG (`OsRng`) for freshness and entropy.

**Potential Weaknesses**:
- Falls back to panics on RNG failure—may deny service; handle `try_generate()` errors.
- Depends on OS RNG security—attackable via OS compromise.
- Allocation size leakage via `Vec<u8>` resizing.

**Mitigations**:
- Prefer `try_generate()` and handle errors gracefully (e.g., retry or fallback mechanisms).
- Deploy in trusted OS environments; monitor for RNG entropy exhaustion.
- Pre-allocate buffers or use fixed-size types to avoid size leaks.

**Review Points**:
- Test RNG failure scenarios; handle errors gracefully.
- Verify entropy source in deployment environment.
- Review encoding integrations for post-generation leaks.

### Constant-Time Equality (`ct_eq.rs`)
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
