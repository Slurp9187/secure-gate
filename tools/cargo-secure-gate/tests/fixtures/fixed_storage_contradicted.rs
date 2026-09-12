// The hole `src/traits/fixed_storage.rs` documents and accepts: "A type with a
// `Vec` field that implements `FixedStorage` anyway will compile and will leak."
// All three must be flagged as errors.
use secure_gate::FixedStorage;

// Direct.
struct Session {
    id: [u8; 16],
    material: Vec<u8>,
}
impl FixedStorage for Session {}

// One level down -- the field that lies is not the field you read first.
struct Inner {
    scratch: String,
}
struct Outer {
    limbs: [u64; 4],
    inner: Inner,
}
impl FixedStorage for Outer {}

// Inside an array, which is the shape SECURITY.md calls out by name:
// "`Fixed<[Vec<u8>; 2]>` hid a growable container inside the very array shape
// this document called exempt".
struct Pair([Vec<u8>; 2]);
impl FixedStorage for Pair {}

// An enum leaks if any variant does.
enum Either {
    Fixed([u8; 32]),
    Grown(Vec<u8>),
}
impl FixedStorage for Either {}
