// The shape SECURITY.md measures at 1016 secret bytes across 7 abandoned blocks
// for a 1008-byte secret. Not a corpus test -- the corpus only pins the fixed
// form -- so this fixture is written from the documented measurement.
// Must be flagged, once per call site rather than once per push.
use secure_gate::{dynamic_newtype, Dynamic};

dynamic_newtype!(pub Tok, Vec<u8>, "A token-shaped secret.");

pub fn fill_byte_by_byte(material: &[u8]) -> Tok {
    Tok::new_with(|v| {
        for byte in material {
            v.push(*byte);
        }
    })
}

// Iterator-driven, one call, an unknown number of reallocations: `repeat_n`
// reserves once and a filter chain grows its way up, and the difference is in a
// trait impl this pass cannot see. Reported as a warning, not an error.
pub fn fill_from_iterator(material: &[u8]) -> Dynamic<Vec<u8>> {
    Dynamic::new_with(|v| {
        v.extend(material.iter().filter(|b| **b != 0).copied());
    })
}

pub fn append_to_string(parts: &[String]) -> Dynamic<String> {
    Dynamic::new_with(|s| {
        for part in parts {
            s.push_str(part);
        }
    })
}
