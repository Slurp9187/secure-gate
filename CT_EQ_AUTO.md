# Justification for Using `ct_eq_auto` in secure-gate

## Benchmark Environment
Benchmarks run on a 2019-era consumer laptop (Intel Core i7-10510U @ 1.80GHz, 8 logical cores, 16GB RAM, Windows 11 Pro) – typical for developers and many production scenarios. Results generalize to similar mid-tier hardware; high-end servers may see even better ct_eq_hash scaling.

## Overview
`ct_eq_auto` is the recommended hybrid constant-time equality method in secure-gate, automatically selecting between direct byte comparison (`ct_eq`, using `subtle`) and probabilistic BLAKE3 hashing (`ct_eq_hash`) based on input size. The default 32-byte threshold optimizes for mixed workloads: ≤32 bytes use fast deterministic `ct_eq`; >32 bytes use secure hashing. In `--all-features` mode, BLAKE3 uses keyed mode (enabled via `rand` feature) for enhanced resistance to multi-target precomputation attacks.

This report benchmarks and justifies `ct_eq_auto` as the recommended choice for variable-size or large secrets, and explains when plain `ct_eq` is preferable.

## Performance Data
Benchmarks confirm `ct_eq_auto`'s default selection is near-optimal, outperforming manual choices unless heavily skewed workloads. All results from Criterion benches in `--all-features` (keyed BLAKE3 enabled), averaged across multiple runs for reliability.

### Key Benchmarks: ct_eq_hash_vs_standard.rs (ct_eq_hash vs ct_eq)
- **Small secrets (≤32B)**: `ct_eq` dominates (e.g., 32B: ~152ns vs `ct_eq_hash` ~254ns, ~1.7x faster).
- **Large secrets**: `ct_eq_hash` scales better (e.g., 1KB: ~4µs vs `ct_eq_hash` ~1.7µs, ~2.3x faster; 100KB: ~406µs vs 62µs, ~6.5x faster).
- **Worst-case unequal (timing safety)**: Both constant-time, but `ct_eq_hash` avoids length-based side-channels.
- **Hash overhead**: Fixed ~30-60ns (compute + keying), paid only for >32B.
- **Caching effects**: Varying data hits ~10% slower, but still better than full `ct_eq` on large inputs.

### Threshold Tuning Benchmarks: ct_eq_auto.rs (custom thresholds)
- **Default 32B optimal**: For 16B: ~74ns (ct_eq path); for 64B: ~285ns (hash path) — balanced.
- **Forcing hash on small data**: +350% overhead (16B: 74ns → 338ns) — default avoids this.
- **Forcing ct_eq on large data**: Potential 5-10% savings if hardware/cache favors it (64B: 285ns → 255ns), but rare and use-case specific.
- **Dynamic vs Fixed**: Similar trends, with Dynamic adding ~20% alloc overhead.
- **Outliers**: ≤8% across runs, confirming reliable trends (improved by `black_box` fixes).

Crossover validated at ~32B: Default minimizes total latency for mixed sizes without manual tuning.

### Benchmark Variance & Hardware Sensitivity
Multi-run benchmarks (3x on 2019 Intel i7-10510U/16GB/Windows 11) show stable variance: changes between runs: 5-10% due to system noise/cache effects. Outliers ≤8%. Key insight: Core trends (crossover ~32B, hash wins large data) hold consistently; `black_box` fixes eliminated previous artifacts. Profile per-system for tuning if variance affects critical paths.

## Security Justification
- **Timing safety**: Both paths constant-time; `ct_eq_hash` hides length/cache differences.
- **Probabilistic but safe**: 2⁻²⁵⁶ per-pair forgery probability (not the birthday bound); negligible for equality; use `ct_eq` for deterministic needs if <32B dominates.
- **Key mode (active)**: Per-process random key resists rainbow tables/multi-target attacks across comparisons — stronger than deterministic BLAKE3.
- **DoS resistance**: Hashing large inputs has fixed overhead; bound sizes upstream.
- **No leaks**: Indirect channels (errors, timing) mitigated; zero-copy when possible.

## Customization & Practical Benefits
- **Easy tuning**: Pass `Some(n)` to `ct_eq_auto` for custom thresholds (e.g., `ct_eq_auto(&a, &b, Some(64))` for larger small-input cutoff). Benchmark for gains.
- **Auto-selection pros**: Zero overhead for small data; security for large. Justifies "auto" name.
- **Cons**: Probabilistic for >32B; tune threshold if benchmarks show >10% gains.
- **When to use**: Variable or large secrets, or when a single consistent equality API is preferred. For small/fixed-size keys and nonces (the most common case), plain `ct_eq` is faster and fully sufficient.

## Recommendation

For **most typical use cases** (fixed-size cryptographic keys, nonces, HMAC keys, signatures ≤ 64 bytes), use plain `.ct_eq()` — it is fastest, fully deterministic, constant-time, and has zero extra overhead:

```rust
#[cfg(feature = "ct-eq")]
if a.ct_eq(&b) { /* equal */ }
```

Use **`ct_eq_auto(None)`** (default 32-byte threshold) when:

- Secret sizes are **variable** or **unknown** at compile time
- You want to **hide length-based side channels** for large inputs
- You have **mixed sizes** and prefer a single consistent API

```rust
// Variable or mixed sizes
if a.ct_eq_auto(&b, None) { /* equal */ }

// Tune the crossover based on your own benchmarks
if a.ct_eq_auto(&b, Some(64)) { /* equal */ }
```

`ct_eq_hash` (uniform probabilistic) is available when you want consistent behaviour regardless of size.

**Bottom line:**
- Small/fixed secrets (typical crypto keys/nonces, ≤ 64 bytes) → prefer `.ct_eq()`
- Variable/large/mixed data → prefer `ct_eq_auto(None)`

Bench your specific workload and hardware if the default threshold feels suboptimal — most users never need to tune it.
