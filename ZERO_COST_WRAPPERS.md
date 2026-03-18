# Justification for Using `secure-gate` Zero-Access-Cost Wrappers

## Benchmark Environment
Benchmarks run on a 2019-era consumer laptop (Intel Core i7-10510U @ 1.80GHz, 8 logical cores, 16GB RAM, Windows 11 Pro) – typical for developers and many production scenarios. Results generalize to similar mid-tier hardware; high-end servers may see even tighter performance.

**Note**: Hardware variance may affect absolute timings—test on your target hardware for precision.

## Overview
secure-gate's `Fixed<T>` and `Dynamic<T>` wrappers enforce explicit, auditable access to sensitive data via methods like `.expose_secret()` or `.with_secret()`, preventing accidental leaks while adding zero runtime overhead for access operations. This "zero-cost access" design means security is compiled in without performance penalties—timings match raw arrays within measurement noise. Benchmarks confirm operations like indexing, array XOR (simulating crypto), and mutable access are indistinguishable from raw `[u8; 32]` access.

This report justifies secure-gate as the ideal choice for secret handling: security without sacrifice, backed by sub-nanosecond benchmarks.

## Performance Data
Multi-run Criterion benches (`fixed_vs_raw.rs` and `dynamic_vs_raw.rs`) compare raw arrays/vectors, explicit `Fixed<T>`/`Dynamic<T>` access, and macro-aliased `Fixed<T>`. All operations on 32B data—results in picoseconds/nanoseconds, with throughput in GiB/s where applicable.

### Fixed<T> Access Patterns & Overhead
- **Single index access**: Raw ~517ps (57.3-58.1 GiB/s) vs Fixed_explicit ~525ps (56.3-57.2 GiB/s) vs Fixed_alias_rawkey ~527ps (56.0-57.0 GiB/s). All three within measurement noise of each other—zero-cost confirmed at the gate to data.
- **Full array XOR (crypto-like)**: Simulates secret mixing/XOR ops. Raw ~520ps (56.8-57.8 GiB/s) vs Fixed_explicit ~523ps (56.5-57.3 GiB/s) vs Fixed_alias_rawkey ~522ps (56.8-57.4 GiB/s). Effectively identical—zero-cost for bulk data manipulation.
- **With_secret scoped access**: Fixed_explicit ~527ps (56.2-57.0 GiB/s). Confirms API equivalence with `expose_secret` within noise.
- **Mutable access (write + read)**: Fixed_explicit ~752ps (39.3-40.0 GiB/s); Fixed_alias_rawkey ~746ps (39.5-40.3 GiB/s). Both identical—alias adds no overhead.

### Fixed<T> Drop Overhead
- **Raw array lifecycle**: ~1.05ns (trivial drop)
- **Fixed lifecycle**: ~17.4ns (includes 32 volatile zero-writes)
- **Fixed alias lifecycle**: ~17.6ns (includes 32 volatile zero-writes)

Drop overhead is ~16-17x the access cost but still sub-20ns for 32B secrets—the intentional security guarantee at an acceptable cost.

### Dynamic<T> Lifecycle Overhead
- **32B raw vec lifecycle**: ~45.6ns (659-680 MiB/s)
- **32B dynamic lifecycle**: ~106.1ns (285-290 MiB/s, includes zeroize)
- **1KB raw vec lifecycle**: ~74.8ns (12.6-12.8 GiB/s)
- **1KB dynamic lifecycle**: ~640.0ns (1.47-1.51 GiB/s, includes zeroize)
- **Spare capacity (1KB alloc, 32B used)**: Raw ~48.6ns vs Dynamic ~330–800ns. The wide Dynamic range reflects allocator-state sensitivity (cold vs warm heap); the zeroize pass always covers the full 1KB allocated capacity regardless.

Dynamic overhead scales linearly with secret size. The 1KB lifecycle result is stable across runs (~640ns) while the 32B results are more allocator-sensitive. Overhead remains within an acceptable range for typical crypto workloads.

### Variance & Scaling
- Run variance: Now stable at 5-10% with proper `black_box` usage. Previous 25% variance was due to constant-folding artifacts in index-access benchmarks, now resolved. Outliers ≤10%.
- Scaling: Times stay sub-nanosecond for access ops, sub-20ns for drop—secure-gate doesn't scale down performance on small secrets.
- Insight: "Zero-cost access" verified; drop overhead is the intentional security guarantee. No excuses for insecure raw arrays when secure alternatives cost nothing extra for access.

## Security Justification
- **Access control**: Raw arrays leak via casual use; secure-gate requires explicit `.expose_secret()`, grep-able and auditable.
- **No silent operations**: Prevents `Deref` leaks; all access is intentional.
- **Memory safety**: Bounds checked, zeroizable; aligns with Rust's principles.
- **Drop safety**: `zeroize` wipes data on drop (unconditional, always enabled).
- **Timing/No leaks**: Doesn't interfere with constant-time ops (e.g., ct_eq); adds no indirect channels.

## Practical Benefits
- **Ease of use**: One-liner wrappers: `Fixed::new([42u8; 32])` vs raw. Macros like `fixed_alias!` for type safety.
- **Zero-cost access in practice**: Devs can secure secrets without worrying about perf hits in hot paths (e.g., key derivation, encryption).
- **Minimal trade-offs**: Security baked in with zero access overhead + bounded drop cost—ideal for performance-critical crypto apps.
- **Cons**: Minor ergonomics (explicit access), but this is the point: forces good habits.

## Recommendation
Always use secure-gate wrappers for secrets—zero access cost, max security. Raw arrays are relics; justify deviations only if proven zero-overhead in your benchmarks. secure-gate proves security doesn't have to slow down access operations, with drop overhead being the intentional security guarantee.
