// The impl from the `FixedStorage` module docs: an ML-KEM-shaped secret
// polynomial, which is exactly what the marker exists to allow.
// Must not be flagged.
use secure_gate::{Fixed, FixedStorage, SentinelValue};
use zeroize::Zeroize;

struct Poly([i16; 256]);

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl SentinelValue for Poly {
    fn sentinel_value() -> Self {
        Poly([0i16; 256])
    }
}
impl FixedStorage for Poly {}

// A boxed slice has a length fixed at construction, so it qualifies too.
struct Boxed(Box<[u8]>);
impl FixedStorage for Boxed {}

// Tuples, arrays and Option payloads resolve through to their elements.
struct Composite {
    limbs: [u64; 4],
    tag: Option<u32>,
    pair: (u8, char),
}
impl FixedStorage for Composite {}
