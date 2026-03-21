# Security Considerations for secure-gate

Last updated: 2026-03 (for v0.8.0-rc.1)

## TL;DR
- **No independent audit** — review the source code yourself before production use.
- **No unsafe code** — `#![forbid(unsafe_code)]` enforced unconditionally.
- **Explicit exposure only** — all secret access requires `.expose_secret()` / `.with_secret()` or mutable equivalents; no `Deref`, `AsRef`, or implicit borrowing.
- **Zeroization on drop** — full buffer (including spare capacity) always wiped on drop (inner type must implement `Zeroize`).
- **Timing-safe equality** — use `ConstantTimeEq` / `.ct_eq()` (`ct-eq`); `==` is deliberately not implemented.
- **Opt-in risk** — cloning and serialization require explicit marker traits (`CloneableSecret`, `SerializableSecret`).
- **Vulnerability reporting** — preferred: GitHub private vulnerability reporting (Security tab); public issues acceptable.

This document outlines the security model, design choices, strengths, known limitations, and review guidance for `secure-gate`.

## What secure-gate does NOT protect against

- **Process compromise / arbitrary memory read** — wrappers offer no defense if an attacker can read process memory
- **OS swap, page files, core dumps** — secrets may be paged to disk; use `mlock` or encrypted swap at the OS level
- **`panic = "abort"` / SIGKILL / hard crash** — `Drop` impls do not run; secrets are not cleared
- **`static` secrets** — Rust does not invoke `Drop` on statics; `Fixed::new` in a `static` is never zeroized
- **Copies made by caller code** — after `expose_secret()`, encoding, or serialization, the caller holds ordinary non-zeroized memory
- **Encoded/serialized output** — `to_hex()`, `to_base64url()`, serde `Serialize` output are full secret exposure into ordinary, non-zeroizing `String`s
- **All side channels beyond equality timing** — cache, power, EM, and branch-predictor side channels are outside scope
- **Allocation-based DoS from deserialization** — `MAX_DESERIALIZE_BYTES` is a post-materialization result-length bound; the upstream deserializer may have already allocated the full payload
- **Stack/register residue outside wrapper control** — temporaries in caller code, FFI boundaries, and compiler-generated spills are not managed by this crate

## Audit Status

`secure-gate` has **not** undergone an independent security audit.

The crate is intentionally small and relies on well-vetted dependencies:

- `zeroize` — memory wiping
- `subtle` — constant-time comparison primitives
- `rand_core` + `getrandom` — secure randomness (via `rand` feature)
- Encoding crates (`hex`, `base64`, `bech32`) — battle-tested (supports bech32 / bech32m)

**Before production use**, review:

- Source code
- Tests:
  - `tests/zeroize_tests.rs` — semantic layer: verifies drop order, API-visible state, and spare-capacity targeting via `PanicOnNonZeroDrop`
  - `tests/heap_zeroize.rs` — physical layer: verifies heap bytes are zeroed before deallocation via `ProxyAllocator` interception
  - `tests/ct_eq_tests.rs` and `tests/proptest_suite/` — timing-safe equality coverage
- Dependency versions and their security history

## Core Security Model

| Property                          | Guarantee / Design Choice                                                                 |
|-----------------------------------|--------------------------------------------------------------------------------------------|
| Explicit exposure                 | Private inner fields; access only via audited methods (`expose_secret`, `with_secret`)   |
| Scoped exposure (preferred)       | Closures limit borrow lifetime; prevents long-lived references                             |
| Direct exposure (escape hatch)    | `expose_secret()` / `expose_secret_mut()` — grep-able, auditable                           |
| No implicit leaks                 | No `Deref`, `AsRef`, `Copy`, `Clone` (unless `cloneable` + marker)                         |
| Zeroization                       | Full allocation always wiped on drop; includes `Vec`/`String` spare capacity (inner type must implement `Zeroize`) |
| Timing safety                     | `ConstantTimeEq` (`.ct_eq()`) — deterministic constant-time comparison. Avoid `==`. |
| Opt-in risky features             | Cloning/serialization gated by marker traits (`CloneableSecret`, `SerializableSecret`)         |
| Redacted debug                    | `Debug` impl always prints `[REDACTED]`                                                    |
| No unsafe code                    | `#![forbid(unsafe_code)]` enforced at crate level                                          |

## Feature Security Implications

| Feature              | Security Impact                                                                 | Recommendation                              |
|----------------------|----------------------------------------------------------------------------------|---------------------------------------------|
| `alloc` *(default)*  | Enables `Dynamic<T>` + full zeroization of `Vec`/`String` spare capacity. Use `default-features = false` for no-heap builds. | Enable unless on embedded/pure-stack target |
| `std`                | Full `std` support (implies `alloc`). Adds no additional security surface beyond `alloc`. | Optional; `alloc` is sufficient for most targets |
| `ct-eq`              | Timing-safe direct byte comparison (`.ct_eq()`)                                  | Strongly recommended; avoid `==`            |
| `rand`               | Secure random via `OsRng`; panics on failure                                     | Use only in trusted entropy environments    |
| `serde-deserialize`  | Direct binary deserialization (arrays/seqs only); no string auto-parsing. Binary-safe; temporary buffers are `Zeroizing`-wrapped. Default 1 MiB limit (`MAX_DESERIALIZE_BYTES`) rejects oversized payloads and zeroizes them before deallocation. Use `Dynamic::deserialize_with_limit` for custom ceilings. **Note:** the limit is a post-materialization result-length bound — the upstream deserializer may have already allocated the full payload. For untrusted input, enforce size limits at the transport or parser layer upstream. | Enable for trusted deserialization sources; set a tight limit for untrusted input and enforce transport-level size caps upstream |
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
- `Fixed<T>` decoding constructors (`try_from_hex`, `try_from_base64url`, etc.) use
  `copy_from_slice` into a stack-allocated `[0u8; N]` before moving into the wrapper.
  The intermediate stack slot is not explicitly zeroed before the move; in adversarial
  environments (core dumps, memory forensics) secret bytes may persist briefly on the
  stack. In release mode the compiler often eliminates the slot entirely. `Dynamic<T>`
  avoids this via `protect_decode_result` + `mem::take` (heap-only path).
- **`static` secrets are never zeroized.** `Fixed::new` is `const fn`, so
  `static SECRET: Fixed<[u8; 32]> = Fixed::new([...]);` compiles without warning.
  Rust does not invoke `Drop` on program-scope statics during the lifetime of the
  process. The `ZeroizeOnDrop` guarantee only applies to values that are dropped in
  the normal sense (stack unwinding, scope exit). Do not store secrets in statics.
- **`panic = "abort"` builds disable zeroization on panic.** When `panic = "abort"`
  is set in a profile, Rust aborts the process immediately on panic without running
  any `Drop` implementations. Secrets held in `Fixed<T>` or `Dynamic<T>` at the
  moment of a panic will not be zeroized before the process exits. This is an
  inherent limitation of the `zeroize` ecosystem — `zeroize`, `secrecy`, and other
  crates share the same constraint. Prefer `panic = "unwind"` (the default) in
  security-sensitive builds.

**Mitigations**
- Prefer `with_secret()` / `with_secret_mut()`
- Audit all `expose_secret()` calls
- Contextualize errors to avoid side-channel information
- Never store a wrapper in a `static` — use local variables or heap-allocated structs instead
- Keep the default `panic = "unwind"` profile in security-sensitive builds; if `panic = "abort"` is required, document and accept the constraint that secrets may not be cleared on panic

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
- Temporary decode buffers in `Dynamic<Vec<u8>>` decoding constructors and `Deserialize`, and `Dynamic<String>` `Deserialize`, are routed through `zeroize::Zeroizing` before being moved into the wrapper, matching `Fixed<T>` and ensuring zeroization if a panic occurs between a successful decode and construction (#96, #97)
- `Dynamic<Vec<u8>>` and `Dynamic<String>` deserialization rejects payloads exceeding `MAX_DESERIALIZE_BYTES` (1 MiB); oversized buffers are zeroized before deallocation. Use `deserialize_with_limit` for custom ceilings. (#99)
- Treat all decoding input as untrusted; validate upstream
- Encoding traits (`ToHex`, `ToBech32`, etc.) are explicit exposure — same contract as `expose_secret`. They are not a bypass. Direct wrapper methods (`key.to_hex()`) are ergonomically safe (no user-visible reference) but do **not** appear in `grep expose_secret` / `grep with_secret` audit sweeps. Use the consolidated grep to surface all encoding exposure points regardless of pattern: `grep -rn 'expose_secret\|with_secret\|\.to_hex\|\.to_base64url\|try_to_bech32\|try_to_bech32m'`. For `expose_secret` + encode: chaining immediately is safe; binding to a named variable that outlives the encoding call is the danger — use only for FFI or third-party APIs requiring a raw `&[u8]` slice. For Bech32/Bech32m decoding into a wrapper, prefer `Fixed::try_from_bech32` / `Dynamic::try_from_bech32` (and `try_from_bech32m`) over the `_unchecked` variants to prevent cross-protocol confusion attacks.
- Use specific traits (e.g., `FromBech32Str`) for strict format enforcement
- Fuzz parsers; sanitize inputs before decoding
- Decoding errors may include format hints — treat as potential metadata leaks in sensitive contexts; redact logs or use custom error display in production
- Audit custom `Cloneable`/`Serializable` impls to preserve zeroization

## Best Practices

- The `alloc` feature is enabled by default and provides `Dynamic<T>` with full zeroization; use `default-features = false` for embedded / pure-stack builds (`Fixed<T>` only)
- Prefer scoped `with_secret()` over long-lived `expose_secret()`
- For equality, use `.ct_eq()` (`ct-eq` feature) for all secret comparisons — deterministic and constant-time. Bound input sizes at the transport/parser layer for untrusted data.
- Audit every `CloneableSecret` / `SerializableSecret` impl
- Validate and sanitize all inputs before encoding/decoding
- Use specific format traits (`FromBech32Str`, `FromHexStr`, …) when the expected format is known
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
