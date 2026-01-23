// benches/fixed_vs_raw.rs
// Zero-cost proof for Fixed<T> and aliases — runs on stable Rust
// Run with: cargo bench --all-features --bench fixed_vs_raw
// → opens HTML report showing negligible overhead (< 0.1 cycles typical)

use criterion::{criterion_group, criterion_main, Criterion};
use secure_gate::{fixed_alias, ExposeSecret, ExposeSecretMut, Fixed};
use std::hint::black_box;

fixed_alias!(pub RawKey, 32); // Alias for semantic testing

fn bench_raw_array(c: &mut Criterion) {
    let key = [42u8; 32];

    let mut group = c.benchmark_group("raw_32b");

    group.bench_function("single index access", |b| {
        b.iter(|| {
            let a = key[0];
            let b = key[15];
            black_box(a ^ b)
        })
    });

    group.bench_function("full array XOR (crypto-like)", |b| {
        b.iter(|| {
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
    let key = Fixed::new([42u8; 32]);
    let mut mut_key = Fixed::new([42u8; 32]);

    let mut group = c.benchmark_group("fixed_explicit_32b");

    group.bench_function("single index access", |b| {
        b.iter(|| {
            let bytes = key.expose_secret();
            let a = bytes[0];
            let b = bytes[15];
            black_box(a ^ b)
        })
    });

    group.bench_function("full array XOR (crypto-like)", |b| {
        b.iter(|| {
            let bytes = key.expose_secret();
            let mut acc = 0u8;
            for &byte in bytes.iter() {
                acc ^= byte;
            }
            black_box(acc)
        })
    });

    group.bench_function("mutable access (write + read)", |b| {
        b.iter(|| {
            let bytes = mut_key.expose_secret_mut();
            bytes[0] = bytes[0].wrapping_add(1);
            black_box(bytes[0])
        })
    });

    group.finish();
}

fn bench_fixed_alias_explicit(c: &mut Criterion) {
    let key = RawKey::new([42u8; 32]);
    let mut mut_key = RawKey::new([42u8; 32]);

    let mut group = c.benchmark_group("fixed_alias_rawkey_32b");

    group.bench_function("single index access", |b| {
        b.iter(|| {
            let bytes = key.expose_secret();
            let a = bytes[0];
            let b = bytes[15];
            black_box(a ^ b)
        })
    });

    group.bench_function("full array XOR (crypto-like)", |b| {
        b.iter(|| {
            let bytes = key.expose_secret();
            let mut acc = 0u8;
            for &byte in bytes.iter() {
                acc ^= byte;
            }
            black_box(acc)
        })
    });

    group.bench_function("mutable access", |b| {
        b.iter(|| {
            let bytes = mut_key.expose_secret_mut();
            bytes[0] = bytes[0].wrapping_add(1);
            black_box(bytes[0])
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_raw_array,
    bench_fixed_explicit,
    bench_fixed_alias_explicit
);
criterion_main!(benches);
