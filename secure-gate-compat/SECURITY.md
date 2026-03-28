# Security Considerations for secure-gate-compat

Compatibility shims for migrating from the [`secrecy`](https://crates.io/crates/secrecy) crate (v0.8.0 and v0.10.1).

**Last updated:** March 2026 (for v0.9.0)

## TL;DR

- Thin transitional layer providing drop-in replacements (`Secret<S>`, `SecretBox<S>`, `SecretString`, etc.) with the same zeroize-on-drop and redacted-`Debug` guarantees as the core library.
- **Use only for migration** — switch to native `secure-gate` types (`Dynamic<T>`, `Fixed<[T; N]>`, `RevealSecret`) as soon as possible.
- Follows the **3-tier access model** (prefer Tier 1): scoped (`with_secret`/`with_secret_mut`), direct (`expose_secret`/`expose_secret_mut`), owned (`into_inner`).
- No unsafe code. All zeroization and access control is delegated to the core crate and `zeroize`.
- Audit for **both** `ExposeSecret` (compat) and `RevealSecret` / `with_secret` (native) during transition.
- **No formal audit or peer review** — this crate has not undergone an official security audit or independent peer review; treat it as experimental until then.

## Key Risks & Mitigations

- **Parallel trait surface** (`ExposeSecret` vs `RevealSecret`): easy to miss access points during migration.  
  *Mitigation*: Search for both `expose_secret` and `with_secret` / `reveal`. Remove `secrecy-compat` feature once complete.

- **Tier 2 direct exposure** (`expose_secret`/`expose_secret_mut`): long-lived references can defeat scoping.  
  *Mitigation*: Prefer Tier 1 scoped methods in application code; audit every Tier 2 use.

- **Tier 3 owned consumption** (`into_inner`): transfers ownership out of wrapper protection and does not appear in `expose_secret` grep sweeps.  
  *Mitigation*: Audit `into_inner` calls separately; zeroization transfers to returned `InnerSecret<T>`.

- **Clone window in conversions** (`SecretBox<S> → Dynamic<S>` requires `S: Clone`): temporary copy before zeroization.  
  *Mitigation*: Prefer `init_with_mut` constructors where possible.

- **Stack residue in v0.8 types** (`Secret<S>` uses inline storage, like core `Fixed<T>`): zeroization on drop is best-effort only.  
  *Mitigation*: Treat values as short-lived. Prefer Tier 1 scoped access (`with_secret`/`with_secret_mut`) to minimize exposure window.

- **serde feature**: serialization is opt-in via `SerializableSecret`.  
  *Mitigation*: Only enable when needed; never serialize secrets unintentionally.

## Best Practices

- Use the compat layer **only during migration**; remove `secrecy-compat` as soon as possible.
- Follow the **3-tier access model** (prefer Tier 1 scoped methods in application code):
  - Tier 1 (preferred): `with_secret` / `with_secret_mut` (scoped borrow)
  - Tier 2 (escape hatch): `expose_secret` / `expose_secret_mut` (direct reference)
  - Tier 3 (rare): `into_inner` (owned consumption — audit separately)
- Enable `secrecy-compat` only on crates that are actively migrating.
- Run the migration test suite (`cargo test --features secrecy-compat` and `--features dual-compat-test`).
- Treat every Tier 2 and Tier 3 call as a security-sensitive audit point.
- Migrate to native `RevealSecret` / `with_secret` API for new code and remove the compat dependency.

## Vulnerability Reporting

Report vulnerabilities through the main repository:

- **Preferred**: [GitHub private vulnerability reporting](https://github.com/Slurp9187/secure-gate/security/advisories/new)
- **Alternative**: Open a draft issue or email the maintainers.

Expected response time: acknowledgment within 48 hours, coordinated disclosure after a fix is prepared.

See the core crate's [SECURITY.md](https://github.com/Slurp9187/secure-gate/blob/main/secure-gate-core/SECURITY.md) for the full policy.

## Disclaimer

This document reflects design intent and observed properties as of the current release.

This crate has not undergone an official security audit or independent peer review. Until then, it should be treated as experimental.

**No warranties are provided**. Users are solely responsible for their own security evaluation, threat modeling, and audit.