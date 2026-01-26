// ==========================================================================
// benches/ct_eq_hash_vs_ct_eq.rs
// ==========================================================================
// Benchmarks comparing ct-eq-hash (Blake3-based) vs ct-eq (subtle-based) performance.
// Expect ct-eq-hash to outperform ct-eq for secrets >128 bytes due to fixed 32b comparison.
//
// Note: When "rand" feature is enabled, ct_eq_hash uses a random key for enhanced security
// (variable output, prevents precomputed rainbow tables). Without "rand", it uses
// deterministic hashing. These benchmarks run in the configured mode.

#[cfg(feature = "ct-eq-hash")]
use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(feature = "ct-eq-hash")]
use std::hint::black_box;

// 32b secret (expect ct-eq to be faster)
#[cfg(feature = "ct-eq-hash")]
#[allow(non_snake_case)]
fn bench_32B_secret_comparison(c: &mut Criterion) {
    use secure_gate::{ConstantTimeEqExt, Fixed};

    let a: Fixed<[u8; 32]> = Fixed::from([1u8; 32]);
    let b: Fixed<[u8; 32]> = Fixed::from([1u8; 32]);

    // ct-eq-hash comparison (ConstantTimeEqExt::ct_eq_hash uses BLAKE3 hash equality)
    c.bench_function("fixed_ct_eq_hash_32b", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_hash(&b)));
    });

    // Ct-eq comparison (direct byte comparison)
    c.bench_function("fixed_ct_eq_32b", |bencher| {
        bencher.iter(|| black_box(a.ct_eq(&b)));
    });
}
// 1kb secret (1024 bytes) (expect ct-eq-hash to be faster)
#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
#[allow(non_snake_case)]
fn bench_1KiB_secret_comparison(c: &mut Criterion) {
    use secure_gate::{ConstantTimeEqExt, Dynamic};

    let a: Dynamic<Vec<u8>> = vec![1u8; 1024].into();
    let b: Dynamic<Vec<u8>> = vec![1u8; 1024].into();

    // ct-eq-hash comparison (ConstantTimeEqExt::ct_eq_hash uses BLAKE3 hash equality)
    c.bench_function("dynamic_ct_eq_hash_1kb", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_hash(&b)));
    });

    // Ct-eq comparison (direct byte comparison)
    c.bench_function("dynamic_ct_eq_1kb", |bencher| {
        bencher.iter(|| black_box(a.ct_eq(&b)));
    });
}

// 100kb secret (102,400 bytes) (massive hash-eq advantage expected)
#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
#[allow(non_snake_case)]
fn bench_100KiB_secret_comparison(c: &mut Criterion) {
    use secure_gate::ConstantTimeEqExt;
    // Mitigate caching: Use fresh allocations with varying data
    // ct-eq-hash comparison (ConstantTimeEqExt::ct_eq_hash uses BLAKE3 hash equality)
    c.bench_function("dynamic_ct_eq_hash_100kb", |bencher| {
        bencher.iter(|| {
            let a: secure_gate::Dynamic<Vec<u8>> = black_box(vec![42u8; 102_400]).into();
            let b: secure_gate::Dynamic<Vec<u8>> = black_box(vec![42u8; 102_400]).into();
            black_box(a.ct_eq_hash(&b))
        });
    });

    c.bench_function("dynamic_ct_eq_100kb", |bencher| {
        bencher.iter(|| {
            let a: secure_gate::Dynamic<Vec<u8>> = black_box(vec![42u8; 102_400]).into();
            let b: secure_gate::Dynamic<Vec<u8>> = black_box(vec![42u8; 102_400]).into();
            black_box(a.ct_eq(&b))
        });
    });
}

// 1mb secret (1,048,576 bytes) (extreme bound for hash-eq fixed overhead)
#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
#[allow(non_snake_case)]
fn bench_1MiB_secret_comparison(c: &mut Criterion) {
    use secure_gate::ConstantTimeEqExt;
    // Mitigate caching: Use fresh allocations with varying data
    // ct-eq-hash comparison (ConstantTimeEqExt::ct_eq_hash uses BLAKE3 hash equality)
    c.bench_function("dynamic_ct_eq_hash_1mb", |bencher| {
        bencher.iter(|| {
            let a: secure_gate::Dynamic<Vec<u8>> = black_box(vec![255u8; 1_048_576]).into(); // ~1mb
            let b: secure_gate::Dynamic<Vec<u8>> = black_box(vec![255u8; 1_048_576]).into();
            black_box(a.ct_eq_hash(&b))
        });
    });

    c.bench_function("dynamic_ct_eq_1mb", |bencher| {
        bencher.iter(|| {
            let a: secure_gate::Dynamic<Vec<u8>> = black_box(vec![255u8; 1_048_576]).into();
            let b: secure_gate::Dynamic<Vec<u8>> = black_box(vec![255u8; 1_048_576]).into();
            black_box(a.ct_eq(&b))
        });
    });
}

// Worst-case unequal comparisons: differ at end (detect timing leaks)
#[cfg(feature = "ct-eq-hash")]
#[allow(non_snake_case)]
fn bench_worst_case_unequal_32B(c: &mut Criterion) {
    use secure_gate::{ConstantTimeEqExt, Fixed};

    let mut group = c.benchmark_group("fixed_unequal_end_32b");

    group.bench_function("ct_eq_hash_differ_at_end", |bencher| {
        bencher.iter(|| {
            let mut data_a = [0u8; 32];
            data_a[31] = 0;
            let a: Fixed<[u8; 32]> = Fixed::from(data_a);

            let mut data_b = [0u8; 32];
            data_b[31] = 1;
            let b: Fixed<[u8; 32]> = Fixed::from(data_b);

            black_box(a.ct_eq_hash(&b))
        });
    });

    group.bench_function("ct_eq_differ_at_end", |bencher| {
        bencher.iter(|| {
            let mut data_a = [0u8; 32];
            data_a[31] = 0;
            let a: Fixed<[u8; 32]> = Fixed::from(data_a);

            let mut data_b = [0u8; 32];
            data_b[31] = 1;
            let b: Fixed<[u8; 32]> = Fixed::from(data_b);

            black_box(a.ct_eq(&b))
        });
    });

    group.finish();
}

// Worst-case unequal comparisons: differ at end (detect timing leaks)
#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
#[allow(non_snake_case)]
fn bench_worst_case_unequal_1KiB(c: &mut Criterion) {
    use secure_gate::{ConstantTimeEqExt, Dynamic};

    let mut group = c.benchmark_group("dynamic_unequal_end_1kb");

    group.bench_function("ct_eq_hash_differ_at_end", |bencher| {
        bencher.iter(|| {
            let mut data_a = vec![0u8; 1024];
            data_a[1023] = 0;
            let a: Dynamic<Vec<u8>> = data_a.into();

            let mut data_b = vec![0u8; 1024];
            data_b[1023] = 1;
            let b: Dynamic<Vec<u8>> = data_b.into();

            black_box(a.ct_eq_hash(&b))
        });
    });

    group.bench_function("ct_eq_differ_at_end", |bencher| {
        bencher.iter(|| {
            let mut data_a = vec![0u8; 1024];
            data_a[1023] = 0;
            let a: Dynamic<Vec<u8>> = data_a.into();

            let mut data_b = vec![0u8; 1024];
            data_b[1023] = 1;
            let b: Dynamic<Vec<u8>> = data_b.into();

            black_box(a.ct_eq(&b))
        });
    });

    group.finish();
}

// Hash computation overhead
#[cfg(feature = "ct-eq-hash")]
fn bench_hash_computation(c: &mut Criterion) {
    // Mitigate caching: Use fresh allocations with varying data
    c.bench_function("hash_compute_32b", |bencher| {
        bencher.iter(|| black_box(blake3::hash(black_box(&[1u8; 32]))));
    });

    c.bench_function("hash_compute_1kb", |bencher| {
        bencher.iter(|| black_box(blake3::hash(black_box(&vec![1u8; 1024]))));
    });

    c.bench_function("hash_compute_100kb", |bencher| {
        bencher.iter(|| black_box(blake3::hash(black_box(&vec![42u8; 102_400]))));
    });

    c.bench_function("hash_compute_1mb", |bencher| {
        bencher.iter(|| black_box(blake3::hash(black_box(&vec![255u8; 1_048_576]))));
    });
}

// Compare keyed (secure, with random key) vs deterministic BLAKE3 hashing performance
#[cfg(feature = "ct-eq-hash")]
#[allow(non_snake_case)]
fn bench_keyed_vs_deterministic_hashing(c: &mut Criterion) {
    // Note: This benchmark compares raw hashing; hash_eq adds caching overhead.
    // Keyed hashing provides security but has slight overhead.
    // Deterministic hashing is faster but predictable.

    // Local fixed key for benchmarking (mimics keyed behavior)
    const BENCH_KEY: [u8; 32] = [42u8; 32];

    c.bench_function("blake3_deterministic_32b", |bencher| {
        bencher.iter(|| black_box(blake3::hash(black_box(&[1u8; 32]))));
    });

    c.bench_function("blake3_keyed_32b", |bencher| {
        bencher.iter(|| {
            black_box(
                blake3::Hasher::new_keyed(&BENCH_KEY)
                    .update(&[1u8; 32])
                    .finalize(),
            )
        });
    });

    c.bench_function("blake3_deterministic_1kb", |bencher| {
        bencher.iter(|| black_box(blake3::hash(black_box(&vec![1u8; 1024]))));
    });

    c.bench_function("blake3_keyed_1kb", |bencher| {
        bencher.iter(|| {
            black_box(
                blake3::Hasher::new_keyed(&BENCH_KEY)
                    .update(&vec![1u8; 1024])
                    .finalize(),
            )
        });
    });
}

// Storage impact note: +32 bytes per instance (negligible for most cases)

// Hash caching effects: Demonstrates performance difference between cached (precomputed hash)
// and non-cached (fresh computation) equality checks.
#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
#[allow(non_snake_case)]
fn bench_ct_eq_hash_caching_effects(c: &mut Criterion) {
    use secure_gate::{ConstantTimeEqExt, Dynamic, Fixed};

    // Fixed data (hash may be cached internally if same)
    c.bench_function("ct_eq_hash_fixed_data_32b", |bencher| {
        let a: Fixed<[u8; 32]> = Fixed::from([42u8; 32]);
        let b: Fixed<[u8; 32]> = Fixed::from([42u8; 32]);
        bencher.iter(|| black_box(a.ct_eq_hash(&b)));
    });

    // Varying data (hash cache miss)
    c.bench_function("ct_eq_hash_varying_data_32b", |bencher| {
        bencher.iter(|| {
            let seed = black_box(0u8); // Prevent const folding
            let a: Fixed<[u8; 32]> = Fixed::from([seed.wrapping_add(1); 32]);
            let b: Fixed<[u8; 32]> = Fixed::from([seed.wrapping_add(1); 32]);
            black_box(a.ct_eq_hash(&b))
        });
    });

    // Fixed data (hash may be cached)
    c.bench_function("ct_eq_hash_fixed_data_1kb", |bencher| {
        let a: Dynamic<Vec<u8>> = vec![42u8; 1024].into();
        let b: Dynamic<Vec<u8>> = vec![42u8; 1024].into();
        bencher.iter(|| black_box(a.ct_eq_hash(&b)));
    });

    // Varying data (hash cache miss)
    c.bench_function("ct_eq_hash_varying_data_1kb", |bencher| {
        bencher.iter(|| {
            let seed = black_box(0u8);
            let a: Dynamic<Vec<u8>> = vec![seed.wrapping_add(1); 1024].into();
            let b: Dynamic<Vec<u8>> = vec![seed.wrapping_add(1); 1024].into();
            black_box(a.ct_eq_hash(&b))
        });
    });
}

#[cfg(feature = "ct-eq-hash")]
criterion_group!(
    name = ct_eq_hash_vs_ct_eq;
    config = Criterion::default();
    targets = bench_32B_secret_comparison, bench_1KiB_secret_comparison, bench_100KiB_secret_comparison, bench_1MiB_secret_comparison, bench_worst_case_unequal_1KiB, bench_ct_eq_hash_caching_effects, bench_hash_computation, bench_keyed_vs_deterministic_hashing, bench_worst_case_unequal_32B
);
#[cfg(feature = "ct-eq-hash")]
criterion_main!(ct_eq_hash_vs_ct_eq);

// No benches when required features are not enabled
#[cfg(not(feature = "ct-eq-hash"))]
fn main() {
    eprintln!("Benchmark requires 'ct-eq-hash' feature. Run with --features ct-eq-hash");
}
