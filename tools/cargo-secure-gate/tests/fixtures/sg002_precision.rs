// Three shapes an adversarial pass reported this check flagging wrongly. None
// is allocator-measured -- they are hand-written probes -- but all three are
// wrong by this check's own stated rule, which calls exactly one bulk fill of an
// empty buffer clean. All must be clean.
use secure_gate::Dynamic;
use std::io::Write;

struct S {
    a: Vec<u8>,
    b: Vec<u8>,
    token: Vec<u8>,
}

// Mutually exclusive branches: one bulk fill runs, whichever way it goes.
pub fn branches(m: &[u8], hex: bool) -> Dynamic<Vec<u8>> {
    Dynamic::new_with(|v| {
        if hex {
            v.extend_from_slice(m)
        } else {
            v.extend_from_slice(&m[..1])
        }
    })
}

// Two different empty fields, one bulk fill each. Counting growth globally
// rather than per access path reported the second as repeated.
pub fn two_fields(x: &[u8], y: &[u8]) -> Dynamic<S> {
    Dynamic::new_with(|s| {
        s.a.extend_from_slice(x);
        s.b.extend_from_slice(y);
    })
}

// A presized field written through a macro. Reading only the first token of
// `write!(s.token, ..)` saw `s`, missed the `s.token` reservation above it, and
// then suggested `s.reserve_exact(len)` -- which would not compile.
pub fn macro_writes(n: usize) -> Dynamic<S> {
    Dynamic::new_with(|s| {
        s.token.reserve_exact(n + 8);
        write!(s.token, "a").unwrap();
        write!(s.token, "b").unwrap();
    })
}

// The contrast: two bulk fills of the SAME field can both run, and must not be
// swept up by the per-path fix.
pub fn same_field_twice(x: &[u8], y: &[u8]) -> Dynamic<S> {
    Dynamic::new_with(|s| {
        s.a.extend_from_slice(x);
        s.a.extend_from_slice(y);
    })
}
