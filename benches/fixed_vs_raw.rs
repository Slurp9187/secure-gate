// benches/fixed_vs_raw.rs
// Zero-cost proof for Fixed<T> in v0.6.1 — runs on stable Rust
// Run with: cargo bench --all-features
// → opens beautiful HTML report showing < 0.1 cycle overhead

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secure_gate::{fixed_alias, Fixed};

fixed_alias!(RawKey, 32);

// === Read access benchmarks ===

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

// === Mutable access benchmarks ===

fn bench_raw_array_mut(c: &mut Criterion) {
    let mut key = [42u8; 32];
    c.bench_function("raw [u8; 32] mutable access", |b| {
        b.iter(|| {
            key[0] ^= key[15];
            black_box(key[0])
        })
    });
}

fn bench_fixed_mut(c: &mut Criterion) {
    let mut key = Fixed::new([42u8; 32]);
    c.bench_function("Fixed<[u8; 32]> mutable .expose_secret_mut()", |b| {
        b.iter(|| {
            let bytes = key.expose_secret_mut();
            bytes[0] ^= bytes[15];
            black_box(bytes[0])
        })
    });
}

// === Construction benchmarks ===

fn bench_raw_array_construction(c: &mut Criterion) {
    c.bench_function("raw [u8; 32] construction", |b| {
        b.iter(|| {
            let key = [42u8; 32];
            black_box(key)
        })
    });
}

fn bench_fixed_construction(c: &mut Criterion) {
    c.bench_function("Fixed<[u8; 32]> construction", |b| {
        b.iter(|| {
            let key = Fixed::new([42u8; 32]);
            black_box(key)
        })
    });
}

// === Zeroize overhead (when enabled) ===

#[cfg(feature = "zeroize")]
fn bench_fixed_drop_with_zeroize(c: &mut Criterion) {
    c.bench_function("Fixed<[u8; 32]> drop (zeroize enabled)", |b| {
        b.iter(|| {
            let key = Fixed::new([42u8; 32]);
            drop(key); // Should zeroize
        })
    });
}

#[cfg(not(feature = "zeroize"))]
fn bench_fixed_drop_without_zeroize(c: &mut Criterion) {
    c.bench_function("Fixed<[u8; 32]> drop (zeroize disabled)", |b| {
        b.iter(|| {
            let key = Fixed::new([42u8; 32]);
            drop(key); // No zeroization
        })
    });
}

// Build criterion group conditionally based on features
#[cfg(feature = "zeroize")]
criterion_group!(
    benches,
    bench_raw_array,
    bench_fixed_explicit,
    bench_fixed_alias_explicit,
    bench_raw_array_mut,
    bench_fixed_mut,
    bench_raw_array_construction,
    bench_fixed_construction,
    bench_fixed_drop_with_zeroize,
);

#[cfg(not(feature = "zeroize"))]
criterion_group!(
    benches,
    bench_raw_array,
    bench_fixed_explicit,
    bench_fixed_alias_explicit,
    bench_raw_array_mut,
    bench_fixed_mut,
    bench_raw_array_construction,
    bench_fixed_construction,
    bench_fixed_drop_without_zeroize,
);

criterion_main!(benches);
