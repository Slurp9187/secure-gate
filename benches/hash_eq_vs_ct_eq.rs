// ==========================================================================
// benches/hash_eq_vs_ct_eq.rs
// ==========================================================================
// Benchmarks comparing hash-eq (Blake3-based) vs ct-eq (subtle-based) performance.
// Expect hash-eq to outperform ct-eq for secrets >128 bytes due to fixed 32B comparison.

#[cfg(feature = "hash-eq")]
use criterion::{criterion_group, criterion_main, Criterion};

// Small secret: 32 B (expect ct-eq to be faster)
#[cfg(feature = "hash-eq")]
fn bench_32B_secret_comparison(c: &mut Criterion) {
    use secure_gate::{Fixed, HashEq};

    let a: Fixed<[u8; 32]> = Fixed::from([1u8; 32]);
    let b: Fixed<[u8; 32]> = Fixed::from([1u8; 32]);

    // Hash-eq comparison (HashEq::hash_eq uses BLAKE3 hash equality)
    c.bench_function("small_fixed_hash_eq", |bencher| {
        bencher.iter(|| criterion::black_box(a.hash_eq(&b)));
    });

    // Ct-eq comparison (direct byte comparison)
    c.bench_function("small_fixed_ct_eq", |bencher| {
        bencher.iter(|| criterion::black_box(a.ct_eq(&b)));
    });
}
// Large secret: 1 KiB (1024 bytes) (expect hash-eq to be faster)
#[cfg(feature = "hash-eq")]
fn bench_1KiB_secret_comparison(c: &mut Criterion) {
    use secure_gate::{Dynamic, HashEq};

    let a: Dynamic<Vec<u8>> = vec![1u8; 1024].into();
    let b: Dynamic<Vec<u8>> = vec![1u8; 1024].into();

    // Hash-eq comparison (HashEq::hash_eq uses BLAKE3 hash equality)
    c.bench_function("large_dynamic_hash_eq", |bencher| {
        bencher.iter(|| criterion::black_box(a.hash_eq(&b)));
    });

    // Ct-eq comparison (direct byte comparison)
    c.bench_function("large_dynamic_ct_eq", |bencher| {
        bencher.iter(|| criterion::black_box(a.ct_eq(&b)));
    });
}

// Ultra-large secret: 100 KiB (102,400 bytes) (massive hash-eq advantage expected)
#[cfg(feature = "hash-eq")]
fn bench_100KiB_secret_comparison(c: &mut Criterion) {
    // Mitigate caching: Use fresh allocations with varying data
    // Hash-eq comparison (HashEq::hash_eq uses BLAKE3 hash equality)
    c.bench_function("ultra_large_dynamic_hash_eq", |bencher| {
        bencher.iter(|| {
            let a: secure_gate::Dynamic<Vec<u8>> = criterion::black_box(vec![42u8; 102_400]).into();
            let b: secure_gate::Dynamic<Vec<u8>> = criterion::black_box(vec![42u8; 102_400]).into();
            criterion::black_box(a.hash_eq(&b))
        });
    });

    c.bench_function("ultra_large_dynamic_ct_eq", |bencher| {
        bencher.iter(|| {
            let a: secure_gate::Dynamic<Vec<u8>> = criterion::black_box(vec![42u8; 102_400]).into();
            let b: secure_gate::Dynamic<Vec<u8>> = criterion::black_box(vec![42u8; 102_400]).into();
            criterion::black_box(a.ct_eq(&b))
        });
    });
}

// Massive secret: 1 MiB (1,048,576 bytes) (extreme bound for hash-eq fixed overhead)
#[cfg(feature = "hash-eq")]
fn bench_1MiB_secret_comparison(c: &mut Criterion) {
    // Mitigate caching: Use fresh allocations with varying data
    // Hash-eq comparison (HashEq::hash_eq uses BLAKE3 hash equality)
    c.bench_function("massive_dynamic_hash_eq", |bencher| {
        bencher.iter(|| {
            let a: secure_gate::Dynamic<Vec<u8>> =
                criterion::black_box(vec![255u8; 1_048_576]).into(); // ~1MiB
            let b: secure_gate::Dynamic<Vec<u8>> =
                criterion::black_box(vec![255u8; 1_048_576]).into();
            criterion::black_box(a.hash_eq(&b))
        });
    });

    c.bench_function("massive_dynamic_ct_eq", |bencher| {
        bencher.iter(|| {
            let a: secure_gate::Dynamic<Vec<u8>> =
                criterion::black_box(vec![255u8; 1_048_576]).into();
            let b: secure_gate::Dynamic<Vec<u8>> =
                criterion::black_box(vec![255u8; 1_048_576]).into();
            criterion::black_box(a.ct_eq(&b))
        });
    });
}

// Worst-case unequal comparisons: differ at end (detect timing leaks)
#[cfg(feature = "hash-eq")]
fn bench_worst_case_unequal_32B(c: &mut Criterion) {
    use secure_gate::Fixed;

    let mut group = c.benchmark_group("32B_fixed_unequal_end");

    group.bench_function("hash_eq_differ_at_end", |bencher| {
        bencher.iter(|| {
            let mut data_a = [0u8; 32];
            data_a[31] = 0;
            let a: Fixed<[u8; 32]> = Fixed::from(data_a);

            let mut data_b = [0u8; 32];
            data_b[31] = 1;
            let b: Fixed<[u8; 32]> = Fixed::from(data_b);

            criterion::black_box(a.hash_eq(&b))
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

            criterion::black_box(a.ct_eq(&b))
        });
    });

    group.finish();
}

#[cfg(feature = "hash-eq")]
fn bench_worst_case_unequal_1KiB(c: &mut Criterion) {
    use secure_gate::Dynamic;

    let mut group = c.benchmark_group("large_dynamic_unequal_end");

    group.bench_function("hash_eq_differ_at_end", |bencher| {
        bencher.iter(|| {
            let mut data_a = vec![0u8; 1024];
            data_a[1023] = 0;
            let a: Dynamic<Vec<u8>> = data_a.into();

            let mut data_b = vec![0u8; 1024];
            data_b[1023] = 1;
            let b: Dynamic<Vec<u8>> = data_b.into();

            criterion::black_box(a.hash_eq(&b))
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

            criterion::black_box(a.ct_eq(&b))
        });
    });

    group.finish();
}

// Hash computation overhead
#[cfg(feature = "hash-eq")]
#[allow(dead_code)]
fn bench_hash_computation(c: &mut Criterion) {
    // Mitigate caching: Use fresh allocations with varying data
    c.bench_function("hash_compute_small", |bencher| {
        bencher.iter(|| criterion::black_box(blake3::hash(criterion::black_box(&[1u8; 32]))));
    });

    c.bench_function("hash_compute_1KiB", |bencher| {
        bencher.iter(|| criterion::black_box(blake3::hash(criterion::black_box(&vec![1u8; 1024]))));
    });

    c.bench_function("hash_compute_100KiB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(blake3::hash(criterion::black_box(&vec![42u8; 102_400])))
        });
    });

    c.bench_function("hash_compute_1MiB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(blake3::hash(criterion::black_box(&vec![255u8; 1_048_576])))
        });
    });
}

// Storage impact note: +32 bytes per instance (negligible for most cases)

#[cfg(feature = "hash-eq")]
criterion_group!(
    name = hash_eq_vs_ct_eq;
    config = Criterion::default();
    targets = bench_32B_secret_comparison, bench_1KiB_secret_comparison, bench_100KiB_secret_comparison, bench_1MiB_secret_comparison, bench_hash_computation, bench_worst_case_unequal_32B, bench_worst_case_unequal_1KiB
);
#[cfg(feature = "hash-eq")]
criterion_main!(hash_eq_vs_ct_eq);

// No benches when required features are not enabled
#[cfg(not(feature = "hash-eq"))]
fn main() {
    println!("Benchmarks require the 'hash-eq' feature to be enabled.");
}
