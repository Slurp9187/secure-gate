// The shape an adversarial pass found missed most often, and the most idiomatic
// in the language: the buffer is never named alone, only a field of it.
// Must be flagged, and the message must name `s.token`, not `s`.
use secure_gate::Dynamic;

struct Session {
    token: Vec<u8>,
    label: String,
    id: [u8; 16],
}

pub fn build(material: &[u8]) -> Dynamic<Session> {
    Dynamic::new_with(|s| {
        for b in material {
            s.token.push(*b);
        }
    })
}

// Sizing one field must not excuse growing another.
pub fn build_half_sized(material: &[u8], label: &str) -> Dynamic<Session> {
    Dynamic::new_with(|s| {
        s.token.reserve_exact(material.len());
        for b in material {
            s.token.push(*b);
        }
        for c in label.chars() {
            s.label.push(c);
        }
    })
}
