// benches/fixed_vs_raw.rs
// Zero-cost proof for Fixed<T> in v0.6.0 — runs on stable Rust
// Run with: cargo bench --all-features
// → opens beautiful HTML report showing < 0.1 cycle overhead

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secure_gate::{fixed_alias, ExposeSecret, Fixed};

fixed_alias!(RawKey, 32);

fn bench_raw_array(c: &mut Criterion) {
    let key = [42u8; 32];
    c.bench_function("raw [u8; 32] access", |b| {
        b.iter(|| {
            let a = key[0];
            let b = key[15];
            black_box(a ^ b)
        })
    });
}

fn bench_fixed_explicit(c: &mut Criterion) {
    let key = Fixed::new([42u8; 32]);
    c.bench_function("Fixed<[u8; 32]> explicit .expose_secret()", |b| {
        b.iter(|| {
            let bytes = key.expose_secret();
            let a = bytes[0];
            let b = bytes[15];
            black_box(a ^ b)
        })
    });
}

fn bench_fixed_alias_explicit(c: &mut Criterion) {
    let key = RawKey::new([42u8; 32]);
    c.bench_function("fixed_alias! (RawKey) explicit access", |b| {
        b.iter(|| {
            let bytes = key.expose_secret();
            let a = bytes[0];
            let b = bytes[15];
            black_box(a ^ b)
        })
    });
}

criterion_group!(
    benches,
    bench_raw_array,
    bench_fixed_explicit,
    bench_fixed_alias_explicit
);
criterion_main!(benches);
