// benches/serde.rs
// Serde performance benchmarks for secure-gate exportable types vs raw
// Run with: cargo bench --features serde,zeroize -- serde
// → measures serialization/deserialization overhead

use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "serde-serialize")]
use secure_gate::ExportableArray;
use serde_json;

#[cfg(feature = "serde-serialize")]
fn bench_exportable_array_serialize(c: &mut Criterion) {
    let key: ExportableArray<32> = [42u8; 32].into();
    c.bench_function("ExportableArray<32> serialize", |b| {
        b.iter(|| {
            let json = serde_json::to_string(&key).unwrap();
            black_box(json)
        })
    });
}

#[cfg(feature = "serde-serialize")]
fn bench_raw_array_serialize(c: &mut Criterion) {
    let key = [42u8; 32];
    c.bench_function("raw [u8; 32] serialize", |b| {
        b.iter(|| {
            let json = serde_json::to_string(&key).unwrap();
            black_box(json)
        })
    });
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
fn bench_exportable_roundtrip(c: &mut Criterion) {
    use secure_gate::{ExposeSecret, Fixed};
    let original: ExportableArray<32> = [42u8; 32].into();
    c.bench_function("ExportableArray<32> roundtrip", |b| {
        b.iter(|| {
            let json = serde_json::to_string(&original).unwrap();
            let deserialized: Fixed<[u8; 32]> = serde_json::from_str(&json).unwrap();
            black_box(deserialized)
        })
    });
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
fn bench_raw_roundtrip(c: &mut Criterion) {
    let original = [42u8; 32];
    c.bench_function("raw [u8; 32] roundtrip", |b| {
        b.iter(|| {
            let json = serde_json::to_string(&original).unwrap();
            let deserialized: [u8; 32] = serde_json::from_str(&json).unwrap();
            black_box(deserialized)
        })
    });
}

#[cfg(feature = "serde-serialize")]
fn serde_benchmarks(c: &mut Criterion) {
    bench_exportable_array_serialize(c);
    bench_raw_array_serialize(c);

    #[cfg(feature = "serde-deserialize")]
    {
        bench_exportable_roundtrip(c);
        bench_raw_roundtrip(c);
    }
}

#[cfg(feature = "serde-serialize")]
criterion_group!(benches, serde_benchmarks);

#[cfg(feature = "serde-serialize")]
criterion_main!(benches);

#[cfg(not(feature = "serde-serialize"))]
fn main() {
    println!("serde-serialize feature not enabled - no benchmarks to run");
}
