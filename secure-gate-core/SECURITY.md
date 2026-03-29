# Security Considerations for secure-gate

Last updated: March 2026 (for v0.9.0-rc.4)

## TL;DR

- **No independent audit** — review the source code yourself before production use.
- **No unsafe code** — `#![forbid(unsafe_code)]` enforced unconditionally.
- **3-tier access model** — explicit hierarchy (prefer Tier 1 scoped methods). Audit Tier 2/3 calls separately.
- **Explicit exposure only** — requires `with_secret`/`expose_secret` (or mutable equivalents); no `Deref`/`AsRef`.
- **Zeroization on drop** — full buffer (incl. spare capacity) is wiped (inner type must implement `Zeroize`).
- **Timing-safe equality** — use `.ct_eq()` (`ct-eq` feature); `==` is deliberately not implemented.
- **Opt-in risk** — cloning/serialization requires marker traits (`CloneableSecret`/`SerializableSecret`).

This document outlines the security model, design choices, strengths, limitations, and review guidance.

## What secure-gate does NOT protect against

- **Process compromise / arbitrary memory read** — wrappers offer no defense if an attacker can read process memory.
- **OS swap, page files, core dumps** — secrets may be paged to disk; use `mlock` or encrypted swap at the OS level.
- **`panic = "abort"` / SIGKILL / hard crash** — `Drop` impls do not run; secrets are not cleared.
- **`static` secrets** — Rust does not invoke `Drop` on statics; `Fixed::new` in a `static` is never zeroized.
- **Copies made by caller code** — after `expose_secret()`, encoding, or serialization, the caller holds ordinary non-zeroized memory.
- **Encoded/serialized output** — `to_hex()`, `to_base64url()`, and serde `Serialize` produce full secrets in ordinary, non-zeroizing `String`s. Prefer the zeroizing variants (`to_*_zeroizing`, `try_to_bech32*_zeroizing`) that return `EncodedSecret` (wrapping `Zeroizing<String>` with redacted `Debug`) when the encoded form must remain sensitive.
- **All side channels beyond equality timing** — cache, power, EM, and branch-predictor attacks are out of scope.
- **Allocation-based DoS from deserialization** — `MAX_DESERIALIZE_BYTES` is a post-materialization bound only; the upstream deserializer may allocate arbitrarily first.
- **Stack/register residue** — temporaries, FFI boundaries, and compiler spills are outside wrapper control.

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

## 3-Tier Access Model
All secret access follows this explicit hierarchy (the table below expands on these tiers):

- **Tier 1 — Scoped borrow (preferred)**: `with_secret` / `with_secret_mut` — borrow ends when closure returns, minimizing exposure.
- **Tier 2 — Direct reference (escape hatch)**: `expose_secret` / `expose_secret_mut` — long-lived references; use only for FFI or third-party APIs requiring `&T`/`&mut T`.
- **Tier 3 — Owned consumption**: `into_inner` — returns `InnerSecret<T>` (wraps `Zeroizing<T>`); zeroization transfers to caller. Audit separately.

**Audit note**: Tier 2 and Tier 3 calls do not appear in simple `expose_secret` grep sweeps and must be reviewed independently.

## Core Security Model


| Property                       | Guarantee / Design Choice                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| Explicit exposure              | Private inner fields; access only via audited methods (`expose_secret`, `with_secret`)                             |
| Scoped exposure (preferred)    | Closures limit borrow lifetime; prevents long-lived references                                                     |
| Direct exposure (escape hatch) | `expose_secret()` / `expose_secret_mut()` — grep-able, auditable                                                   |
| No implicit leaks              | No `Deref`, `AsRef`, `Copy`, `Clone` (unless `cloneable` + marker)                                                 |
| Zeroization                    | Full allocation always wiped on drop; includes `Vec`/`String` spare capacity (inner type must implement `Zeroize`) |
| Timing safety                  | `ConstantTimeEq` (`.ct_eq()`) — deterministic constant-time comparison. Avoid `==`.                                |
| Opt-in risky features          | Cloning/serialization gated by marker traits (`CloneableSecret`, `SerializableSecret`)                             |
| Redacted debug                 | `Debug` impl always prints `[REDACTED]`                                                                            |
| No unsafe code                 | `#![forbid(unsafe_code)]` enforced at crate level                                                                  |


## Feature Security Implications


| Feature             | Security Impact                                                                                                                                                           | Recommendation                                                                                                                   |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `alloc` *(default)* | Enables `Dynamic<T>` + full zeroization of `Vec`/`String` spare capacity. Use `default-features = false` for no-heap builds.                                              | Enable unless on embedded/pure-stack target                                                                                      |
| `std`               | Full `std` support (implies `alloc`). Adds no additional security surface beyond `alloc`.                                                                                 | Optional; `alloc` is sufficient for most targets                                                                                 |
| `ct-eq`             | Timing-safe direct byte comparison (`.ct_eq()`)                                                                                                                           | Strongly recommended; avoid `==`                                                                                                 |
| `rand`              | `from_random()` uses system `SysRng` (`rand` 0.10) and panics on failure; `from_rng()` accepts caller-supplied `TryRng + TryCryptoRng` and returns `Result`            | Use trusted entropy sources; prefer `from_rng()` where RNG failure should be handled explicitly                                 |
| `serde-deserialize` | Decodes to inner type; temporary buffers use `zeroize::Zeroizing` (zeroized on rejection too). 1 MiB default limit (`MAX_DESERIALIZE_BYTES`). See allocation notes below. | Enable for trusted deserialization sources; set a tight limit for untrusted input and enforce transport-level size caps upstream |
| `serde-serialize`   | Opt-in export via marker trait; audit all implementations                                                                                                                 | Enable sparingly; monitor exfiltration risk                                                                                      |
| `encoding`          | Meta: enables all encoding sub-features (hex, base64url, bech32, bech32m); always requires `alloc`                                                                        | Enable per-format instead for minimal surface                                                                                    |
| `encoding-hex`      | Hex encoding/decoding: `ToHex`, `FromHexStr`; requires `alloc`                                                                                                            | Validate inputs upstream; prefer `try_from_hex`                                                                                  |
| `encoding-base64`   | Base64url encoding/decoding: `ToBase64Url`, `FromBase64UrlStr`; requires `alloc`                                                                                          | Validate inputs upstream; prefer `try_from_base64url`                                                                            |
| `encoding-bech32`   | Bech32/BIP-173 encoding/decoding: `ToBech32`, `FromBech32Str`                                                                                                             | Validate inputs upstream; test empty/invalid HRP                                                                                 |
| `encoding-bech32m`  | Bech32m/BIP-350 encoding/decoding: `ToBech32m`, `FromBech32mStr`                                                                                                          | Validate inputs upstream; test empty/invalid HRP                                                                                 |
| `cloneable`         | Opt-in cloning via marker trait; increases exposure surface                                                                                                               | Use minimally; prefer move semantics                                                                                             |
| `full`              | All features enabled — convenient but increases attack surface                                                                                                            | Development only; audit for production                                                                                           |


#### `serde-deserialize` — Allocation & Limit Notes

`MAX_DESERIALIZE_BYTES` (default 1 MiB) and `deserialize_with_limit` are enforced **after** the upstream deserializer has fully materialized the payload — they are result-length acceptance bounds, not pre-allocation guards. For untrusted input, enforce size limits at the transport or parser layer upstream to prevent allocation-based DoS.

## Best Practices

> See the [TL;DR](#tldr) for the shortest version of the most important points.

- Prefer **Tier 1 scoped methods** (`with_secret`/`with_secret_mut`) in application code to minimize lifetime.
- Audit every Tier 2 (`expose_*`) and Tier 3 (`into_inner`) call site separately — they do not appear in simple `expose_secret` grep sweeps.
- Use `alloc` (default) for `Dynamic<T>` zeroization; disable for pure-stack `Fixed<T>` builds.
- Use `.ct_eq()` (`ct-eq` feature) for comparisons; avoid `==`. Bound untrusted input size at the transport/parser layer.
- Audit all `CloneableSecret`/`SerializableSecret` implementations.
- Validate inputs before encoding/decoding or using format-specific traits.
- For encoding: prefer zeroizing methods (`to_hex_zeroizing`, `to_base64url_zeroizing`, `try_to_bech32_zeroizing`, `try_to_bech32m_zeroizing`) that return `EncodedSecret` when the encoded value should remain protected.
- Monitor dependencies for CVEs.
- Treat secrets as radioactive — minimize exposure surface.

## Module-by-Module Security Notes

> Security invariants (no `Deref`/`AsRef`, `Debug` prints `[REDACTED]`, zeroize on drop, opt-in clone/serialize) are documented in full on the `[Fixed](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html)` and `[Dynamic](https://docs.rs/secure-gate/latest/secure_gate/struct.Dynamic.html)` rustdoc. This section focuses on weaknesses and mitigations not visible from the API surface.

### Wrappers (`dynamic.rs`, `fixed.rs`)

**Potential weaknesses**

- Long-lived `expose_secret()` references can defeat scoping
- Macro-generated aliases lack runtime size checks
- Certain error variants may indirectly leak length information (e.g. wrong decoded length).
  In most real-world usage (logging, API responses), length is already public metadata anyway (e.g. key length in JWT headers, signature length). Still, contextualize or redact errors when possible.
- `Fixed<T>` decode constructors previously used `copy_from_slice` into a separate
  stack-allocated `[0u8; N]` before wrapping. **This has been mitigated**: all
  library-internal decode paths (`try_from_hex`, `try_from_base64url`, `try_from_bech32*`,
  `TryFrom<&[u8]>`) and the RNG constructors (`from_random`, `from_rng`) now use
  `Fixed::new_with`, which writes directly into the wrapper's storage and avoids the
  intermediate slot. The `new(value)` constructor still accepts a pre-constructed array
  and may produce a brief stack temporary (compiler often eliminates it at opt-level ≥ 1
  with `#[inline(always)]`). `Dynamic<T>` avoids all stack involvement via
  `from_protected_bytes` + `mem::swap` (heap-only path).
- **`static` secrets are never zeroized.** `Fixed::new` is `const fn`, so
  `static SECRET: Fixed<[u8; 32]> = Fixed::new([...]);` compiles without warning.
  Rust does not invoke `Drop` on program-scope statics during the lifetime of the
  process. The `ZeroizeOnDrop` guarantee only applies to values that are dropped in
  the normal sense (stack unwinding, scope exit). Do not store secrets in statics.
- **`Dynamic::into_inner` allocates a small sentinel `Box` (24 bytes on 64-bit).**
  This is a new availability surface: on pathologically memory-pressured systems the
  sentinel allocation can OOM. Confidentiality is preserved — if `Box::new` panics
  before the swap, `self.inner` still holds the real secret and `Dynamic::drop` zeroizes
  it during unwind. `Fixed::into_inner` is zero-cost (no allocation).
- **`into_inner` now returns `InnerSecret<T>` with redacted `Debug`.**
  `InnerSecret<T>` restores the wrapper-level `[REDACTED]` invariant after ownership
  transfer by implementing `Debug` as constant redaction. Use
  `InnerSecret::into_zeroizing()` only when interoperability requires the raw
  `Zeroizing<T>` wrapper.
- **`panic = "abort"` builds disable zeroization on panic.** When `panic = "abort"`
  is set in a profile, Rust aborts the process immediately on panic without running
  any `Drop` implementations. Secrets held in `Fixed<T>` or `Dynamic<T>` at the
  moment of a panic will not be zeroized before the process exits. This is an
  inherent limitation of the `zeroize` ecosystem — `zeroize`, `secrecy`, and other
  crates share the same constraint. Prefer `panic = "unwind"` (the default) in
  security-sensitive builds.

**Mitigations**

- **For accessing secrets:** prefer the scoped `with_secret()` / `with_secret_mut()` closures
  over `expose_secret()` / `expose_secret_mut()` — they keep the exposed reference tightly
  bound and make accidental long-lived borrows visible at the call site.
- **For constructing secrets:** prefer `Fixed::new_with(|arr| { ... })` or
  `Dynamic::<Vec<u8>>::new_with(|v| { ... })` / `Dynamic::<String>::new_with(|s| { ... })`
  over `Fixed::new(value)` / `Dynamic::new(value)` when constructing from computed data
  inline — these write directly into the wrapper's storage and avoid any intermediate copy.
  `Dynamic<T>` remains the strictest option (heap-only; secret bytes never on the stack).

**Security-first construction and access patterns**

Just as `with_secret` / `with_secret_mut` are the recommended scoped methods for *accessing*
secrets — keeping the exposed reference tightly bound to the closure lifetime —
`Fixed::new_with` is the recommended constructor for *building* `Fixed` secrets when
minimizing stack residue matters. It writes secret material **directly** into the wrapper's
own storage, eliminating the intermediate stack temporary that can exist with the ergonomic
`new(value)` constructor.

`Dynamic<T>` is already heap-only (`from_protected_bytes` + `mem::swap`), so its
`new_with` variants (`Dynamic::<Vec<u8>>::new_with` / `Dynamic::<String>::new_with`)
exist purely for API symmetry — not because `Dynamic` carries any stack-residue risk.
If stack residue is a concern, `Dynamic<T>` remains the strictest overall choice.

For high-assurance `Fixed` construction, prefer:

- `Fixed::new_with(|arr| { … })` over `Fixed::new(value)`

The regular `new(value)` constructors and `expose_secret` / `expose_secret_mut` remain
available as convenient defaults and auditable escape hatches respectively. This mirrors a
consistent "scoped / minimal lifetime" philosophy across both construction and access — the
same defensive mindset applied throughout the crate.

- Audit all `expose_secret()` calls
- Contextualize errors to avoid side-channel information
- Never store a wrapper in a `static` — use local variables or heap-allocated structs instead
- Keep the default `panic = "unwind"` profile in security-sensitive builds; if `panic = "abort"` is required, document and accept the constraint that secrets may not be cleared on panic

Zero-cost claim: performance is indistinguishable from raw arrays (see benchmarks in the test suite and `size_of_val` assertions); the wrapper adds no runtime overhead beyond the required zeroization on drop.

### Traits (`traits/`)

**Potential weaknesses**

- Generic impls assume caller trustworthiness

**Mitigations**

- Audit every `CloneableSecret` / `SerializableSecret` impl — each is a deliberate security decision
- Validate inputs before trait usage

### Encoding/Decoding (Traits & Errors)

#### Untrusted Input & Format Enforcement

- Validate and sanitize all inputs before any decoding operation
- Use specific traits (`FromBech32Str`, `FromHexStr`, `FromBase64UrlStr`) when the expected format is known — they enforce strict parsing rules
- Fuzz parsers and boundary cases in CI; treat all decoding input as untrusted
- Temporary decode buffers for `Dynamic<Vec<u8>>` and `Dynamic<String>` constructors and `Deserialize` impls are wrapped in `zeroize::Zeroizing` — buffers are zeroized even if a panic occurs between a successful decode and wrapper construction (#96, #97)
- `Dynamic<Vec<u8>>` and `Dynamic<String>` deserialization rejects payloads exceeding `MAX_DESERIALIZE_BYTES` (1 MiB); oversized buffers are zeroized before deallocation. Use `deserialize_with_limit` for custom ceilings. (#99)

#### Audit Surfaces

All secret materialization requires an explicit call. Use `rg`, `grep -rn`, or your editor's project-wide search for these method names:

```
expose_secret  expose_secret_mut  with_secret  with_secret_mut
into_inner
to_hex  to_base64url  try_to_bech32  try_to_bech32m
to_hex_zeroizing  to_hex_upper_zeroizing  to_base64url_zeroizing
try_to_bech32_zeroizing  try_to_bech32m_zeroizing
```

**Note:** `into_inner` does not appear in an `expose_secret*`-only sweep — audit it
separately. It consumes the wrapper and transfers ownership to a `Zeroizing<T>`;
the caller is responsible for letting it drop normally (no `mem::forget`).

Encoding traits (`ToHex`, `ToBech32`, etc.) are **explicit secret exposure** — they will not appear in an `expose_secret`-only sweep, so audit them separately.

For `expose_secret` + encode: chaining immediately is safe; binding to a named variable that outlives the encoding call is the risk — use only for FFI or APIs requiring a raw `&[u8]` slice. Prefer `Fixed::try_from_bech32` / `Dynamic::try_from_bech32` (and `*_bech32m`) over `_unchecked` variants to prevent cross-protocol confusion attacks (BIP-173 vs BIP-350).

#### Error Metadata (debug vs release)

In **debug builds** (`cfg(debug_assertions)`), decoding errors include detailed hints — expected vs actual lengths, received HRP values, and encoding hint strings — to aid development and testing. In **release builds** these details are stripped; only broad error categories remain (e.g. `"invalid bech32 string"`, `"decoded length mismatch"`). This is intentional to prevent length/HRP oracles.

Prefer `Display` (`{}`) over `Debug` (`{:?}`) when logging errors in production — derived `Debug` exposes struct fields in debug builds and may be more verbose than intended.

Coarse error categories are still present in release and can aid attacker fingerprinting in niche threat models. Redact or suppress error details in logs for high-sensitivity contexts.

## Encoding: Sensitive vs. Public Output

Encoding methods on `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` come in two flavors:

| Variant | Return type | Zeroized? | When to use |
| ------- | ----------- | --------- | ----------- |
| `to_hex()`, `to_base64url()`, `try_to_bech32()`, `try_to_bech32m()` | `String` / `Result<String, _>` | No | Public encodings — transaction IDs, addresses, non-sensitive identifiers |
| `to_hex_zeroizing()`, `to_base64url_zeroizing()`, `try_to_bech32_zeroizing()`, `try_to_bech32m_zeroizing()` | `EncodedSecret` / `Result<EncodedSecret, _>` | Yes (on drop) | Sensitive encodings — private keys, long-lived tokens, full secret exports |

`EncodedSecret` wraps `Zeroizing<String>`, redacts `Debug` as `[REDACTED]`, and zeroizes the string buffer on drop. Keep values in this form as long as possible.

**Escape hatches:**

- `EncodedSecret::into_inner()` → returns a plain `String`, ends zeroization protection. Use only when an API requires ownership of `String`.
- `EncodedSecret::into_zeroizing()` → returns `Zeroizing<String>`, preserves zeroization. Prefer this when a downstream API accepts `Zeroizing<String>`.

## Vulnerability Reporting

- **Preferred**: GitHub private vulnerability reporting (Repository → Security → Report a vulnerability)
- **Alternative**: Public issue or draft
- **Expected response**: Acknowledgment within 48 hours; coordinated disclosure
- **Public disclosure**: After fix is released and users have reasonable time to update

## Disclaimer

This document reflects design intent and observed properties as of the current release.

**No warranties are provided**. Users are solely responsible for their own security evaluation, threat modeling, and audit.
