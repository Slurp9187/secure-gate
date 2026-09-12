// A peer sweep of this crate found that binding the exposed reference to a local
// defeats a text-based matcher. It defeated the first draft of this pass too,
// and silently -- the worst way to fail, since a miss reads exactly like a pass.
// Must be flagged: `alias` and `v` are the same buffer.
use secure_gate::Dynamic;

pub fn build(material: &[u8]) -> Dynamic<Vec<u8>> {
    Dynamic::new_with(|v| {
        let alias = v;
        for b in material {
            alias.push(*b);
        }
    })
}

// Reborrowing spells it differently and means the same thing.
pub fn build_reborrowed(material: &[u8]) -> Dynamic<Vec<u8>> {
    Dynamic::new_with(|v| {
        let alias = &mut *v;
        for b in material {
            alias.push(*b);
        }
    })
}

// A binding derived from the buffer is not the buffer, and must not be treated
// as one.
pub fn build_presized(material: &[u8]) -> Dynamic<Vec<u8>> {
    Dynamic::new_with(|v| {
        v.reserve_exact(material.len());
        let count = v.capacity();
        let _ = count;
        for b in material {
            v.push(*b);
        }
    })
}
