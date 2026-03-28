# secure-gate Roadmap

**Last updated:** March 2026

secure-gate is a small, single-developer crate for in-memory secret protection.

---

## Release branches

| Branch | Version | Rust edition | MSRV | Status |
|---|---|---|---|---|
| `main` | 0.9.x | 2024 | 1.85 | Active development |
| `release/0.8` | 0.8.x | 2021 | 1.70 | LTS — security patches only |

**Users on Rust < 1.85**: pin `secure-gate = "0.8"` in `Cargo.toml`.
**Modern users (Rust ≥ 1.85)**: use `secure-gate = "0.9"`.

Security fixes and important bug fixes may be backported from `main` to `release/0.8` as patch releases (0.8.x).
The 0.8 line will receive patches as long as the dependencies it relies on remain compatible with Rust 1.70.

---

## 0.9.x (current — `main`)

The 0.9.0 release delivers the modernization of the crate's toolchain and dependency baseline:

- Rust 2024 edition
- MSRV raised to 1.85
- `rand` 0.9 → 0.10 (`OsRng` → `SysRng`)
- `bincode` 1 → 2 (serde-compat API in tests)
- All dependencies updated to latest compatible versions

### Planned for 0.9.x

- Optional memory pinning (`mlock` / `VirtualLock` / `MADV_DONTDUMP`)
  - Simple API: `pin()` → auto-unpin on drop

- Better HSM/TPM escape hatches
  - Safe raw-pointer / file-descriptor helpers + examples

---

## Longer term (v1.0 and beyond)

- Stabilize any new APIs added in 0.9.x
- Documentation refresh
- External review (only if usage grows or help appears)

---

## Out of scope

- Key derivation, sharing, rotation, protocols
- Hardware wallet abstractions
- CPU register / speculative mitigations

---

Contributions welcome — bug reports, docs, small PRs that stay in scope.
