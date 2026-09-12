// A single bulk fill of the empty buffer `new_with` hands over: one allocation,
// and nothing to abandon, because there is no earlier buffer. This is what the
// crate's own `dynamic_vec_new_with_fills_correctly` does.
// Must not be flagged -- the measured shape is a closure that fills byte by byte.
use secure_gate::Dynamic;

pub fn from_slice(material: &[u8]) -> Dynamic<Vec<u8>> {
    Dynamic::<Vec<u8>>::new_with(|v| v.extend_from_slice(material))
}

pub fn from_str(material: &str) -> Dynamic<String> {
    Dynamic::<String>::new_with(|s| s.push_str(material))
}

// Two bulk fills is a different matter: the second may reallocate, and the
// buffer the first one filled is what gets abandoned.
pub fn two_fills(head: &[u8], tail: &[u8]) -> Dynamic<Vec<u8>> {
    Dynamic::<Vec<u8>>::new_with(|v| {
        v.extend_from_slice(head);
        v.extend_from_slice(tail);
    })
}
