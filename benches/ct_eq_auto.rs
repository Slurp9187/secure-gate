// ==========================================================================
// benches/ct_eq_auto.rs
// ==========================================================================
// Benchmarks for ct_eq_auto (automatic hybrid equality) with various threshold points.
// Compares default 32B threshold vs. custom (e.g., 16B, 64B, 0 for always hash, high for always ct_eq).
// Shows optimal tuning: lower for conservative hash, higher for ct_eq on faster hw.

#[cfg(feature = "ct-eq-hash")]
use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(feature = "ct-eq-hash")]
use std::hint::black_box;

#[cfg(feature = "ct-eq-hash")]
use secure_gate::{ConstantTimeEqExt, Fixed};

#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
use secure_gate::Dynamic;

// Fixed arrays: 16B (below default threshold)
#[cfg(feature = "ct-eq-hash")]
#[allow(non_snake_case)]
fn bench_ct_eq_auto_16B_thresholds(c: &mut Criterion) {
    let a: Fixed<[u8; 16]> = Fixed::from([42u8; 16]);
    let b: Fixed<[u8; 16]> = Fixed::from([42u8; 16]);

    let mut group = c.benchmark_group("fixed_ct_eq_auto_16b");

    group.bench_function("default_32b", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, None)));
    });
    group.bench_function("thresh_0_force_hash", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(0))));
    });
    group.bench_function("thresh_16_force_ct_eq", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(16))));
    });
    group.bench_function("thresh_64_force_ct_eq", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(64))));
    });

    group.finish();
}

// Fixed arrays: 32B (at default threshold)
#[cfg(feature = "ct-eq-hash")]
#[allow(non_snake_case)]
fn bench_ct_eq_auto_32B_thresholds(c: &mut Criterion) {
    let a: Fixed<[u8; 32]> = Fixed::from([42u8; 32]);
    let b: Fixed<[u8; 32]> = Fixed::from([42u8; 32]);

    let mut group = c.benchmark_group("fixed_ct_eq_auto_32b");

    group.bench_function("default_32b", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, None)));
    });
    group.bench_function("thresh_0_force_hash", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(0))));
    });
    group.bench_function("thresh_16_force_ct_eq", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(16))));
    });
    group.bench_function("thresh_64_force_hash", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(64))));
    });

    group.finish();
}

// Fixed arrays: 64B (above default threshold)
#[cfg(feature = "ct-eq-hash")]
#[allow(non_snake_case)]
fn bench_ct_eq_auto_64B_thresholds(c: &mut Criterion) {
    let a: Fixed<[u8; 64]> = Fixed::from([42u8; 64]);
    let b: Fixed<[u8; 64]> = Fixed::from([42u8; 64]);

    let mut group = c.benchmark_group("fixed_ct_eq_auto_64b");

    group.bench_function("default_32b", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, None)));
    });
    group.bench_function("thresh_0_force_hash", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(0))));
    });
    group.bench_function("thresh_64_force_ct_eq", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(64))));
    });
    group.bench_function("thresh_128_force_ct_eq", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(128))));
    });

    group.finish();
}

// Dynamic: 128B (above threshold, test force ct_eq)
#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
#[allow(non_snake_case)]
fn bench_ct_eq_auto_128B_dynamic_thresholds(c: &mut Criterion) {
    let a: Dynamic<Vec<u8>> = vec![42u8; 128].into();
    let b: Dynamic<Vec<u8>> = vec![42u8; 128].into();

    let mut group = c.benchmark_group("dynamic_ct_eq_auto_128b");

    group.bench_function("default_32b", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, None)));
    });
    group.bench_function("thresh_64_force_ct_eq", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(64))));
    });
    group.bench_function("thresh_256_force_ct_eq", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(256))));
    });

    group.finish();
}

// Dynamic: 1KB (large, default vs. force ct_eq at high thresh)
#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
#[allow(non_snake_case)]
fn bench_ct_eq_auto_1KiB_dynamic_thresholds(c: &mut Criterion) {
    let a: Dynamic<Vec<u8>> = vec![42u8; 1024].into();
    let b: Dynamic<Vec<u8>> = vec![42u8; 1024].into();

    let mut group = c.benchmark_group("dynamic_ct_eq_auto_1kb");

    group.bench_function("default_32b", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, None)));
    });
    group.bench_function("thresh_512_force_ct_eq", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(512))));
    });
    group.bench_function("thresh_2048_force_ct_eq", |bencher| {
        bencher.iter(|| black_box(a.ct_eq_auto(&b, Some(2048))));
    });

    group.finish();
}

#[cfg(all(feature = "ct-eq-hash", not(feature = "alloc")))]
criterion_group!(
    name = ct_eq_auto_benches;
    config = Criterion::default();
    targets = bench_ct_eq_auto_16B_thresholds, bench_ct_eq_auto_32B_thresholds, bench_ct_eq_auto_64B_thresholds
);

#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
criterion_group!(
    name = ct_eq_auto_benches;
    config = Criterion::default();
    targets = bench_ct_eq_auto_16B_thresholds, bench_ct_eq_auto_32B_thresholds, bench_ct_eq_auto_64B_thresholds,
             bench_ct_eq_auto_128B_dynamic_thresholds, bench_ct_eq_auto_1KiB_dynamic_thresholds
);
#[cfg(all(feature = "ct-eq-hash", not(feature = "alloc")))]
criterion_main!(ct_eq_auto_benches);

#[cfg(all(feature = "ct-eq-hash", feature = "alloc"))]
criterion_main!(ct_eq_auto_benches);

// No benches when required features are not enabled
#[cfg(not(feature = "ct-eq-hash"))]
fn main() {
    eprintln!("Benchmark requires 'ct-eq-hash' feature. Run with --features ct-eq-hash");
}
