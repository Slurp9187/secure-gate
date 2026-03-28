// benches/fixed_vs_raw.rs
// Zero-cost proof for Fixed<T> and aliases — runs on stable Rust
// Run with: cargo bench --all-features --bench fixed_vs_raw
// → opens HTML report showing negligible overhead (< 0.1 cycles typical)

use criterion::{criterion_group, criterion_main, Criterion};
use secure_gate::{fixed_alias, RevealSecret, RevealSecretMut, Fixed};
use std::hint::black_box;

fixed_alias!(pub RawKey, 32); // Alias for semantic testing

fn bench_raw_array(c: &mut Criterion) {
    let key = black_box([42u8; 32]);

    let mut group = c.benchmark_group("raw_32b");
    group.throughput(criterion::Throughput::Bytes(32));

    group.bench_function("single index access", |bencher| {
        bencher.iter(|| {
            let a = key[0];
            let b_byte = key[15];
            black_box(a ^ b_byte)
        })
    });

    group.bench_function("full array XOR (crypto-like)", |bencher| {
        bencher.iter(|| {
            let mut acc = 0u8;
            for &byte in key.iter() {
                acc ^= byte;
            }
            black_box(acc)
        })
    });

    group.finish();
}

fn bench_fixed_explicit(c: &mut Criterion) {
    let key = Fixed::new(black_box([42u8; 32]));
    let mut mut_key = Fixed::new(black_box([42u8; 32]));

    let mut group = c.benchmark_group("fixed_explicit_32b");
    group.throughput(criterion::Throughput::Bytes(32));

    group.bench_function("single index access", |bencher| {
        bencher.iter(|| {
            let bytes = key.expose_secret();
            let a = bytes[0];
            let b_byte = bytes[15];
            black_box(a ^ b_byte)
        })
    });

    group.bench_function("full array XOR (crypto-like)", |bencher| {
        bencher.iter(|| {
            let bytes = key.expose_secret();
            let mut acc = 0u8;
            for &byte in bytes.iter() {
                acc ^= byte;
            }
            black_box(acc)
        })
    });

    group.bench_function("mutable access (write + read)", |bencher| {
        bencher.iter(|| {
            let bytes = mut_key.expose_secret_mut();
            bytes[0] = bytes[0].wrapping_add(1);
            black_box(bytes[0])
        })
    });

    group.bench_function("with_secret scoped access", |bencher| {
        bencher.iter(|| {
            key.with_secret(|bytes| {
                let a = bytes[0];
                let b_byte = bytes[15];
                black_box(a ^ b_byte)
            })
        })
    });

    group.finish();
}

fn bench_fixed_alias_explicit(c: &mut Criterion) {
    let key = RawKey::new(black_box([42u8; 32]));
    let mut mut_key = RawKey::new(black_box([42u8; 32]));

    let mut group = c.benchmark_group("fixed_alias_rawkey_32b");
    group.throughput(criterion::Throughput::Bytes(32));

    group.bench_function("single index access", |bencher| {
        bencher.iter(|| {
            let bytes = key.expose_secret();
            let a = bytes[0];
            let b_byte = bytes[15];
            black_box(a ^ b_byte)
        })
    });

    group.bench_function("full array XOR (crypto-like)", |bencher| {
        bencher.iter(|| {
            let bytes = key.expose_secret();
            let mut acc = 0u8;
            for &byte in bytes.iter() {
                acc ^= byte;
            }
            black_box(acc)
        })
    });

    group.bench_function("mutable access", |bencher| {
        bencher.iter(|| {
            let bytes = mut_key.expose_secret_mut();
            bytes[0] = bytes[0].wrapping_add(1);
            black_box(bytes[0])
        })
    });

    group.finish();
}

fn bench_drop_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("drop_overhead_32b");

    group.bench_function("raw_array_lifecycle", |bencher| {
        bencher.iter(|| {
            let key = black_box([42u8; 32]);
            black_box(key[0])
        })
    });

    group.bench_function("fixed_lifecycle", |bencher| {
        bencher.iter(|| {
            let key = Fixed::new(black_box([42u8; 32]));
            black_box(key.expose_secret()[0])
        })
    });

    group.bench_function("fixed_alias_lifecycle", |bencher| {
        bencher.iter(|| {
            let key = RawKey::new(black_box([42u8; 32]));
            black_box(key.expose_secret()[0])
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_raw_array,
    bench_fixed_explicit,
    bench_fixed_alias_explicit,
    bench_drop_overhead
);
criterion_main!(benches);
