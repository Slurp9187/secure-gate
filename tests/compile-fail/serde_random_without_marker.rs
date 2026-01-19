// This file should NOT compile when "serde-serialize" and "rand" are enabled.
// It verifies that random wrappers cannot be serialized without an explicit
// user-provided impl SerializableSecret for the inner type.
//
// Expected failures:
// - No Serialize for FixedRandom<32> (missing marker on [u8; 32])
// - No Serialize for DynamicRandom (missing marker on Vec<u8>)

#[cfg(all(feature = "serde-serialize", feature = "rand"))]
fn main() {
    use secure_gate::random::{DynamicRandom, FixedRandom};

    let fixed: FixedRandom<32> = FixedRandom::generate();
    let dyn_rand: DynamicRandom = DynamicRandom::generate(64);

    // These lines must cause compile errors due to missing SerializableSecret
    let _ = serde_json::to_string(&fixed);
    let _ = serde_json::to_string(&dyn_rand);
}

#[cfg(not(all(feature = "serde-serialize", feature = "rand")))]
fn main() {
    // Irrelevant when features disabled
}
