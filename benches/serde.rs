// benches/serde.rs
// Serde performance benchmarks for secure-gate exportable types vs raw
// Run with: cargo bench --features serde,zeroize --bench serde
// → measures serialization/deserialization overhead

extern crate alloc;

#[cfg(any(feature = "serde-serialize", feature = "serde-deserialize"))]
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(any(feature = "serde-serialize", feature = "serde-deserialize"))]
use std::hint::black_box;

#[cfg(any(feature = "serde-serialize", feature = "serde-deserialize"))]
use serde_json::{from_str, to_string};

#[cfg(feature = "serde-serialize")]
use secure_gate::SerializableType;

#[cfg(feature = "serde-serialize")]
#[derive(serde::Serialize)]
struct SerializableArray32([u8; 32]);

#[cfg(feature = "serde-serialize")]
impl SerializableType for SerializableArray32 {}

#[cfg(feature = "serde-serialize")]
#[derive(serde::Serialize)]
struct SerializableVec(Vec<u8>);

#[cfg(feature = "serde-serialize")]
impl SerializableType for SerializableVec {}

#[cfg(feature = "serde-serialize")]
#[derive(serde::Serialize)]
struct SerializableString(String);

#[cfg(feature = "serde-serialize")]
impl SerializableType for SerializableString {}

#[cfg(feature = "serde-serialize")]
fn bench_fixed_serialize(c: &mut Criterion) {
    let exportable = SerializableArray32([42u8; 32]);
    let raw = [42u8; 32];

    c.bench_function("SerializableArray32 serialize", |b| {
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

    let exportable = SerializableArray32([42u8; 32]);
    let raw = [42u8; 32];

    c.bench_function("SerializableArray32 → Fixed<[u8; 32]> roundtrip", |b| {
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

    let exportable_vec = SerializableVec(data_vec.clone());
    let exportable_str = SerializableString(data_str.clone());

    let mut group = c.benchmark_group("dynamic_1kb");

    group.bench_function("SerializableVec serialize", |b| {
        b.iter(|| {
            let json = to_string(black_box(&exportable_vec)).unwrap();
            black_box(json)
        })
    });

    group.bench_function("SerializableString serialize", |b| {
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

#[cfg(feature = "serde-serialize")]
fn bench_large_dynamic_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("dynamic_1mb");

    group.bench_function("SerializableVec serialize", |b| {
        b.iter(|| {
            let exportable_vec = SerializableVec(black_box(vec![42u8; 1_048_576]));
            let json = to_string(black_box(&exportable_vec)).unwrap();
            black_box(json)
        })
    });

    group.bench_function("SerializableString serialize", |b| {
        b.iter(|| {
            let exportable_str = SerializableString(black_box("A".repeat(1_048_576)));
            let json = to_string(black_box(&exportable_str)).unwrap();
            black_box(json)
        })
    });

    group.bench_function("raw Vec<u8> serialize", |b| {
        b.iter(|| {
            let data_vec = black_box(vec![42u8; 1_048_576]);
            let json = to_string(black_box(&data_vec)).unwrap();
            black_box(json)
        })
    });

    group.bench_function("raw String serialize", |b| {
        b.iter(|| {
            let data_str = black_box("A".repeat(1_048_576));
            let json = to_string(black_box(&data_str)).unwrap();
            black_box(json)
        })
    });

    group.finish();
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
fn bench_large_dynamic_roundtrip(c: &mut Criterion) {
    use secure_gate::Dynamic;

    let mut group = c.benchmark_group("dynamic_roundtrip_1mb");

    group.bench_function("SerializableVec → Dynamic<Vec<u8>>", |b| {
        b.iter(|| {
            let exportable_vec = SerializableVec(black_box(vec![42u8; 1_048_576]));
            let json = to_string(black_box(&exportable_vec)).unwrap();
            let deserialized: Dynamic<Vec<u8>> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });

    group.bench_function("SerializableString → Dynamic<String>", |b| {
        b.iter(|| {
            let exportable_str = SerializableString(black_box("A".repeat(1_048_576)));
            let json = to_string(black_box(&exportable_str)).unwrap();
            let deserialized: Dynamic<String> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });

    group.bench_function("raw Vec<u8> → Dynamic<Vec<u8>> roundtrip", |b| {
        b.iter(|| {
            let data_vec = black_box(vec![42u8; 1_048_576]);
            let json = to_string(black_box(&data_vec)).unwrap();
            let deserialized: Dynamic<Vec<u8>> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });

    group.bench_function("raw String → Dynamic<String> roundtrip", |b| {
        b.iter(|| {
            let data_str = black_box("A".repeat(1_048_576));
            let json = to_string(black_box(&data_str)).unwrap();
            let deserialized: Dynamic<String> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });

    group.finish();
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
fn bench_dynamic_roundtrip(c: &mut Criterion) {
    use secure_gate::Dynamic;

    let data_vec = vec![42u8; 1024];
    let data_str = "A".repeat(1024);

    let exportable_vec = SerializableVec(data_vec.clone());
    let exportable_str = SerializableString(data_str.clone());

    let mut group = c.benchmark_group("dynamic_roundtrip_1kb");

    group.bench_function("SerializableVec → Dynamic<Vec<u8>>", |b| {
        b.iter(|| {
            let json = to_string(black_box(&exportable_vec)).unwrap();
            let deserialized: Dynamic<Vec<u8>> = from_str(&json).unwrap();
            black_box(deserialized)
        })
    });

    group.bench_function("SerializableString → Dynamic<String>", |b| {
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

    bench_large_dynamic_serialize(c);
    #[cfg(feature = "serde-deserialize")]
    bench_large_dynamic_roundtrip(c);
}

#[cfg(feature = "serde-serialize")]
criterion_group!(benches, serde_benchmarks);
#[cfg(feature = "serde-serialize")]
criterion_main!(benches);

#[cfg(not(feature = "serde-serialize"))]
fn main() {
    println!("serde-serialize feature not enabled - no benchmarks to run");
}
