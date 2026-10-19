// benches/sealed_vs_fixed.rs
// What sealing costs: access, mutation and sealing for SealedFixed<32> beside Fixed<[u8; 32]>,
// a sealed 4 KiB Vec, and Prekey creation (allocation, RNG fill, page lock).
// Run with: cargo bench --features sealed --bench sealed_vs_fixed

use criterion::{Criterion, criterion_group, criterion_main};
use secure_gate::{
    Dynamic, Fixed, Prekey, RevealSecret, RevealSecretMut, SealedDynamic, SealedFixed,
};
use std::hint::black_box;

fn bench_fixed_32(c: &mut Criterion) {
    let prekey = Prekey::new();
    let plain = Fixed::new(black_box([42u8; 32]));
    let mut plain_mut = Fixed::new(black_box([42u8; 32]));
    let sealed = SealedFixed::seal(Fixed::new([42u8; 32]), &prekey);
    let mut sealed_mut = SealedFixed::seal(Fixed::new([42u8; 32]), &prekey);

    let mut group = c.benchmark_group("key_32b");
    group.bench_function("Fixed with_secret", |b| {
        b.iter(|| plain.with_secret(|k| black_box(k[0] ^ k[31])))
    });
    group.bench_function("SealedFixed with_secret", |b| {
        b.iter(|| sealed.with_secret(|k| black_box(k[0] ^ k[31])))
    });
    group.bench_function("Fixed with_secret_mut", |b| {
        b.iter(|| plain_mut.with_secret_mut(|k| k[0] = black_box(k[0].wrapping_add(1))))
    });
    group.bench_function("SealedFixed with_secret_mut", |b| {
        b.iter(|| sealed_mut.with_secret_mut(|k| k[0] = black_box(k[0].wrapping_add(1))))
    });
    group.bench_function("SealedFixed seal", |b| {
        b.iter(|| SealedFixed::seal(Fixed::new(black_box([1u8; 32])), &prekey))
    });
    group.finish();
}

fn bench_dynamic_4k(c: &mut Criterion) {
    let prekey = Prekey::new();
    let plain = Dynamic::<Vec<u8>>::new(vec![7u8; 4096]);
    let sealed = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(vec![7u8; 4096]), &prekey);

    let mut group = c.benchmark_group("vec_4kib");
    group.throughput(criterion::Throughput::Bytes(4096));
    group.bench_function("Dynamic with_secret", |b| {
        b.iter(|| plain.with_secret(|v| black_box(v[0] ^ v[4095])))
    });
    group.bench_function("SealedDynamic with_secret", |b| {
        b.iter(|| sealed.with_secret(|v: &Vec<u8>| black_box(v[0] ^ v[4095])))
    });
    group.finish();
}

fn bench_prekey(c: &mut Criterion) {
    c.bench_function("Prekey::new (alloc + RNG + lock + wipe on drop)", |b| {
        b.iter(|| black_box(Prekey::new()))
    });
}

criterion_group!(benches, bench_fixed_32, bench_dynamic_4k, bench_prekey);
criterion_main!(benches);
