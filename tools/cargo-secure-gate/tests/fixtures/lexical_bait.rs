// Bait for a matcher that reads text rather than syntax: the trigger phrases
// appear in a comment and in a string literal, and there is an unrelated
// `Vec::push` in the same function as a real construction.
// impl FixedStorage for NotReal {}
// Must be clean.
use secure_gate::Dynamic;

pub fn decoy() -> Dynamic<Vec<u8>> {
    let doc = "impl FixedStorage for AlsoNotReal {} // v.push(x)";
    let mut unrelated: Vec<u8> = Vec::new();
    for b in doc.bytes() {
        unrelated.push(b);
    }
    Dynamic::<Vec<u8>>::new_with(|v| v.extend_from_slice(&unrelated))
}
