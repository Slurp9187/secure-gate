// ==========================================================================
// benches/hash_eq_vs_ct_eq.rs
// ==========================================================================
// Benchmarks comparing hash-eq (Blake3-based) vs ct-eq (subtle-based) performance.
// Expect hash-eq to outperform ct-eq for secrets >128 bytes due to fixed 32B comparison.

#[cfg(all(feature = "hash-eq", feature = "ct-eq"))]
use criterion::{criterion_group, criterion_main, Criterion};

// Small secret: 32 bytes (expect ct-eq to be faster)
#[cfg(all(feature = "hash-eq", feature = "ct-eq"))]
fn bench_small_secret_comparison(c: &mut Criterion) {
    use secure_gate::Fixed;

    let a: Fixed<[u8; 32]> = Fixed::from([1u8; 32]);
    let b: Fixed<[u8; 32]> = Fixed::from([1u8; 32]);

    // Hash-eq comparison (== uses Blake3 hash equality)
    c.bench_function("small_fixed_hash_eq", |bencher| {
        bencher.iter(|| criterion::black_box(a == b));
    });

    // Ct-eq comparison (direct byte comparison)
    c.bench_function("small_fixed_ct_eq", |bencher| {
        bencher.iter(|| criterion::black_box(a.ct_eq(&b)));
    });
}

// Large secret: 1000 bytes (expect hash-eq to be faster)
#[cfg(all(feature = "hash-eq", feature = "ct-eq"))]
fn bench_large_secret_comparison(c: &mut Criterion) {
    use secure_gate::Dynamic;

    let a: Dynamic<Vec<u8>> = vec![1u8; 1000].into();
    let b: Dynamic<Vec<u8>> = vec![1u8; 1000].into();

    // Hash-eq comparison (== uses Blake3 hash equality)
    c.bench_function("large_dynamic_hash_eq", |bencher| {
        bencher.iter(|| criterion::black_box(a == b));
    });

    // Ct-eq comparison (direct byte comparison)
    c.bench_function("large_dynamic_ct_eq", |bencher| {
        bencher.iter(|| criterion::black_box(a.ct_eq(&b)));
    });
}

// Hash computation overhead
#[cfg(feature = "hash-eq")]
#[allow(dead_code)]
fn bench_hash_computation(c: &mut Criterion) {
    use blake3::hash;

    let small_data = [1u8; 32];
    let large_data = vec![1u8; 1000];

    c.bench_function("hash_compute_small", |bencher| {
        bencher.iter(|| criterion::black_box(hash(criterion::black_box(&small_data))));
    });

    c.bench_function("hash_compute_large", |bencher| {
        bencher.iter(|| criterion::black_box(hash(criterion::black_box(&large_data))));
    });
}

// Storage impact note: +32 bytes per instance (negligible for most cases)

#[cfg(all(feature = "hash-eq", feature = "ct-eq"))]
criterion_group!(
    name = hash_eq_vs_ct_eq;
    config = Criterion::default();
    targets = bench_small_secret_comparison, bench_large_secret_comparison, bench_hash_computation
);
#[cfg(all(feature = "hash-eq", feature = "ct-eq"))]
criterion_main!(hash_eq_vs_ct_eq);

// No benches when required features are not enabled
#[cfg(not(all(feature = "hash-eq", feature = "ct-eq")))]
fn main() {
    println!("Benchmarks require both 'hash-eq' and 'ct-eq' features to be enabled.");
}
