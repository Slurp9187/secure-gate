# secure-gate Roadmap

**Last updated:** March 2026

secure-gate is a small, single-developer crate for in-memory secret protection.

Current version (0.8.0) delivers the core goals:
- zero-cost explicit access
- mandatory zeroization on drop
- encoding/decoding, ct-eq, serde, random

### Next steps (v0.9.0)

- Optional memory pinning (`mlock` / `VirtualLock` / `MADV_DONTDUMP`)
  - Simple API: `pin()` → auto-unpin on drop

- Better HSM/TPM escape hatches
  - Safe raw-pointer / file-descriptor helpers + examples

### Longer term (v1.0 and beyond)

- Stabilize any new APIs
- Documentation refresh
- External review (only if usage grows or help appears)

### Out of scope

- Key derivation, sharing, rotation, protocols
- Hardware wallet abstractions
- CPU register / speculative mitigations

Contributions welcome — bug reports, docs, small PRs that stay in scope.