# Security Considerations for secure-gate

## TL;DR
- **Zeroize on drop**, redacted `Debug`, **no `Deref`/`AsRef`**, explicit access only.
- **No formal audit or peer review** — this crate has not undergone an official security audit or independent peer review; treat it as experimental until then.
- Follows a **3-tier access model** (prefer Tier 1 in all code):
  1. Scoped (preferred): `with_secret` / `with_secret_mut`
  2. Direct (escape hatch): `expose_secret` / `expose_secret_mut`
  3. Owned (rare): `into_inner`
- Audit Tier 2 and Tier 3 calls separately — they do not appear in simple `expose_secret` grep sweeps.
- No unsafe code. All guarantees rely on `zeroize` and careful API design.

## 3-Tier Access Model
All secret access follows this explicit hierarchy:

- **Tier 1 — Scoped borrow (preferred)**: `with_secret` / `with_secret_mut` — borrow ends when closure returns, minimizing exposure.
- **Tier 2 — Direct reference (escape hatch)**: `expose_secret` / `expose_secret_mut` — long-lived references; use only for FFI or third-party APIs requiring `&T`/`&mut T`.
- **Tier 3 — Owned consumption**: `into_inner` — returns `InnerSecret<T>` (wraps `Zeroizing<T>`); zeroization transfers to caller. Audit separately.

**Audit note**: `into_inner` calls must be reviewed independently.

## Core Invariants
- `Drop` always calls `zeroize()` on the inner value.
- `Debug` never leaks contents (`[REDACTED]`).
- No implicit borrowing (`Deref`, `AsRef`, `AsMut`).
- Metadata (`len`, `is_empty`) is always safe to call.
- `serde` serialization is opt-in via `SerializableSecret`.

## What secure-gate does NOT Protect Against
- **Process compromise / arbitrary memory read** — wrappers offer no defense if an attacker can read process memory.
- **OS swap, page files, core dumps** — secrets may be paged to disk; use `mlock` or encrypted swap at the OS level.
- **`panic = "abort"` / SIGKILL / hard crash** — `Drop` impls do not run; secrets are not cleared.
- **`static` secrets** — Rust does not invoke `Drop` on statics; `Fixed::new` in a `static` is never zeroized.
- **Copies made by caller code** — after `expose_secret()`, encoding, or serialization, the caller holds ordinary non-zeroized memory.
- **Encoded/serialized output** — `to_hex()`, `to_base64url()`, serde `Serialize` output are full secret exposure into ordinary, non-zeroizing `String`s.
- **All side channels beyond equality timing** — cache, power, EM, and branch-predictor side channels are outside scope (enable `ct-eq` feature for constant-time equality where needed).
- **Allocation-based DoS from deserialization** — `MAX_DESERIALIZE_BYTES` (and `deserialize_with_limit`) is only a post-materialization result-length acceptance bound. The upstream deserializer may have already allocated the full payload. For untrusted inputs, enforce size limits at the transport or parser layer upstream before deserialization.
- **Stack/register residue outside wrapper control** — temporaries in caller code, FFI boundaries, and compiler-generated spills are not managed by this crate.
- Bugs in `zeroize`, the allocator, or the OS.
- Improper use of Tier 2/3 methods.

## Best Practices
- Prefer Tier 1 scoped methods in all application code.
- Audit every Tier 2 (`expose_*`) and Tier 3 (`into_inner`) call site.
- Use `with_secret` / `with_secret_mut` to limit secret lifetime.
- Enable `serde-serialize` / `serde-deserialize` only when needed.
- For `serde-deserialize` on untrusted data: enforce size limits at the transport or parser layer upstream before passing to the deserializer (see `deserialize_with_limit` docs).
- Run full test suite (`cargo test --all-features`).
- For encoding: chain immediately or audit the binding lifetime.

## Vulnerability Reporting
- **Preferred**: [GitHub private vulnerability reporting](https://github.com/Slurp9187/secure-gate/security/advisories/new)
- **Alternative**: Draft issue or direct contact.
- Expected response: acknowledgment within 48 hours, coordinated disclosure.

## Disclaimer
This document reflects design intent as of the current release.

This crate has not undergone an official security audit or independent peer review. Until then, it should be treated as experimental.

**No warranties are provided**. Users are solely responsible for their own security evaluation, threat modeling, and audit.
```
