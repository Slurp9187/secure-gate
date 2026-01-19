// benches/serde.rs
// Serde performance benchmarks for secure-gate exportable types vs raw
// Run with: cargo bench --features serde,zeroize --bench serde
// → measures serialization/deserialization overhead

#[cfg(any(feature = "serde-serialize", feature = "serde-deserialize"))]
use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(any(feature = "serde-serialize", feature = "serde-deserialize"))]
use serde_json::{from_str, to_string};

#[cfg(feature = "serde-serialize")]
use secure_gate::{ExportableArray, ExportableString, ExportableVec};

#[cfg(feature = "serde-serialize")]
fn bench_fixed_serialize(c: &mut Criterion) {
    let exportable: ExportableArray<32> = [42u8; 32].into();
    let raw = [42u8; 32];

    c.bench_function("ExportableArray<32> serialize", |b| {
        b.iter(|| {
            let json = to_string(black_box(&exportable)).unwrap();
            black_box(json)
        })
    });

    c.bench_function("raw [u8; 32] serialize", |b| {
        b.iter(|| {
            let json = to_string(black_box(&raw)).unwrap();
            black_box(json)
        })
    });
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
fn bench_fixed_roundtrip(c: &mut Criterion) {
    use secure_gate::Fixed;

    let exportable: ExportableArray<32> = [42u8; 32].into();
    let raw = [42u8; 32];

    c.bench_function("ExportableArray<32> → Fixed<[u8; 32]> roundtrip", |b| {
        b.iter(|| {
            let json = to_string(black_box(&exportable)).unwrap();
            let deserialized: Fixed<[u8; 32]> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });

    c.bench_function("raw [u8; 32] → Fixed<[u8; 32]> roundtrip", |b| {
        b.iter(|| {
            let json = to_string(black_box(&raw)).unwrap();
            let deserialized: Fixed<[u8; 32]> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });
}

#[cfg(feature = "serde-serialize")]
fn bench_dynamic_serialize(c: &mut Criterion) {
    let data_vec = vec![42u8; 1024];
    let data_str = "A".repeat(1024);

    let exportable_vec: ExportableVec = data_vec.clone().into();
    let exportable_str: ExportableString = data_str.clone().into();

    let mut group = c.benchmark_group("dynamic (1KB)");

    group.bench_function("ExportableVec serialize", |b| {
        b.iter(|| {
            let json = to_string(black_box(&exportable_vec)).unwrap();
            black_box(json)
        })
    });

    group.bench_function("ExportableString serialize", |b| {
        b.iter(|| {
            let json = to_string(black_box(&exportable_str)).unwrap();
            black_box(json)
        })
    });

    group.bench_function("raw Vec<u8> serialize", |b| {
        b.iter(|| {
            let json = to_string(black_box(&data_vec)).unwrap();
            black_box(json)
        })
    });

    group.bench_function("raw String serialize", |b| {
        b.iter(|| {
            let json = to_string(black_box(&data_str)).unwrap();
            black_box(json)
        })
    });

    group.finish();
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
fn bench_dynamic_roundtrip(c: &mut Criterion) {
    use secure_gate::Dynamic;

    let data_vec = vec![42u8; 1024];
    let data_str = "A".repeat(1024);

    let exportable_vec: ExportableVec = data_vec.clone().into();
    let exportable_str: ExportableString = data_str.clone().into();

    let mut group = c.benchmark_group("dynamic roundtrip (1KB)");

    group.bench_function("ExportableVec → Dynamic<Vec<u8>>", |b| {
        b.iter(|| {
            let json = to_string(black_box(&exportable_vec)).unwrap();
            let deserialized: Dynamic<Vec<u8>> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });

    group.bench_function("ExportableString → Dynamic<String>", |b| {
        b.iter(|| {
            let json = to_string(black_box(&exportable_str)).unwrap();
            let deserialized: Dynamic<String> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });

    group.bench_function("raw Vec<u8> → Dynamic<Vec<u8>> roundtrip", |b| {
        b.iter(|| {
            let json = to_string(black_box(&data_vec)).unwrap();
            let deserialized: Dynamic<Vec<u8>> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });

    group.bench_function("raw String → Dynamic<String> roundtrip", |b| {
        b.iter(|| {
            let json = to_string(black_box(&data_str)).unwrap();
            let deserialized: Dynamic<String> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });

    group.finish();
}

#[cfg(feature = "serde-serialize")]
fn serde_benchmarks(c: &mut Criterion) {
    bench_fixed_serialize(c);
    #[cfg(feature = "serde-deserialize")]
    bench_fixed_roundtrip(c);

    bench_dynamic_serialize(c);
    #[cfg(feature = "serde-deserialize")]
    bench_dynamic_roundtrip(c);
}

#[cfg(feature = "serde-serialize")]
criterion_group!(benches, serde_benchmarks);
#[cfg(feature = "serde-serialize")]
criterion_main!(benches);

#[cfg(not(feature = "serde-serialize"))]
fn main() {
    println!("serde-serialize feature not enabled - no benchmarks to run");
}
