// benches/dynamic_vs_raw.rs
// Lifecycle overhead proof for Dynamic<T> vs raw Vec — shows zeroize-on-drop cost
// Run with: cargo bench --bench dynamic_vs_raw
// → compares raw Vec lifecycle vs Dynamic<T> (includes zeroize of live + spare capacity)

#[cfg(feature = "alloc")]
use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(feature = "alloc")]
use secure_gate::{Dynamic, RevealSecret};

#[cfg(feature = "alloc")]
use std::hint::black_box;

#[cfg(feature = "alloc")]
fn bench_dynamic_lifecycle_32b(c: &mut Criterion) {
    let mut group = c.benchmark_group("drop_overhead_dynamic_32b");
    group.throughput(criterion::Throughput::Bytes(32));

    group.bench_function("raw_vec_lifecycle", |bencher| {
        bencher.iter(|| {
            let mut v = Vec::with_capacity(black_box(32));
            v.extend_from_slice(&black_box([42u8; 32]));
            black_box(v[0])
        })
    });

    group.bench_function("dynamic_lifecycle", |bencher| {
        bencher.iter(|| {
            let mut v = Vec::with_capacity(black_box(32));
            v.extend_from_slice(&black_box([42u8; 32]));
            let d: Dynamic<Vec<u8>> = Dynamic::new(v);
            black_box(d.expose_secret()[0])
        })
    });

    group.finish();
}

#[cfg(feature = "alloc")]
fn bench_dynamic_lifecycle_1kb(c: &mut Criterion) {
    let mut group = c.benchmark_group("drop_overhead_dynamic_1kb");
    group.throughput(criterion::Throughput::Bytes(1024));

    group.bench_function("raw_vec_lifecycle", |bencher| {
        bencher.iter(|| {
            let mut v = Vec::with_capacity(black_box(1024));
            v.extend_from_slice(&black_box([42u8; 1024]));
            black_box(v[0])
        })
    });

    group.bench_function("dynamic_lifecycle", |bencher| {
        bencher.iter(|| {
            let mut v = Vec::with_capacity(black_box(1024));
            v.extend_from_slice(&black_box([42u8; 1024]));
            let d: Dynamic<Vec<u8>> = Dynamic::new(v);
            black_box(d.expose_secret()[0])
        })
    });

    group.finish();
}

#[cfg(feature = "alloc")]
fn bench_dynamic_spare_capacity(c: &mut Criterion) {
    let mut group = c.benchmark_group("drop_overhead_dynamic_spare_cap");

    group.bench_function("raw_vec_spare_cap_lifecycle", |bencher| {
        bencher.iter(|| {
            let mut v = Vec::with_capacity(black_box(1024));
            v.extend_from_slice(&black_box([42u8; 32]));
            black_box(v[0])
        })
    });

    group.bench_function("dynamic_spare_cap_lifecycle", |bencher| {
        bencher.iter(|| {
            let mut v = Vec::with_capacity(black_box(1024));
            v.extend_from_slice(&black_box([42u8; 32]));
            let d: Dynamic<Vec<u8>> = Dynamic::new(v);
            black_box(d.expose_secret()[0])
        })
    });

    group.finish();
}

#[cfg(feature = "alloc")]
criterion_group!(
    benches,
    bench_dynamic_lifecycle_32b,
    bench_dynamic_lifecycle_1kb,
    bench_dynamic_spare_capacity
);

#[cfg(feature = "alloc")]
criterion_main!(benches);

// No benches when alloc feature is not enabled
#[cfg(not(feature = "alloc"))]
fn main() {
    eprintln!("Benchmark requires 'alloc' feature. Run with --features alloc");
}
