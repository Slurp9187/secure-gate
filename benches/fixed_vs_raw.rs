// benches/fixed_vs_raw.rs
// Zero-cost proof for Fixed<T> — runs on stable Rust
// Run with: cargo bench → opens beautiful HTML report

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secure_gate::{fixed_alias, Fixed};

fixed_alias!(RawKey, 32);

fn bench_raw_array(c: &mut Criterion) {
    let key = [42u8; 32];
    c.bench_function("raw [u8; 32] access", |b| {
        b.iter(|| black_box(key[0] ^ key[15]))
    });
}

fn bench_fixed(c: &mut Criterion) {
    let key = Fixed::new([42u8; 32]);
    c.bench_function("Fixed<[u8; 32]> access", |b| {
        b.iter(|| black_box(key[0] ^ key[15]))
    });
}

fn bench_fixed_alias(c: &mut Criterion) {
    let key = RawKey::new([42u8; 32]);
    c.bench_function("fixed_alias! (RawKey) access", |b| {
        b.iter(|| black_box(key[0] ^ key[15]))
    });
}

criterion_group!(benches, bench_raw_array, bench_fixed, bench_fixed_alias);
criterion_main!(benches);
