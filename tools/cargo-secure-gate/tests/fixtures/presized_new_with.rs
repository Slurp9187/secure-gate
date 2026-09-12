// Derived from `check_new_with_keeps_the_closures_buffer` in
// tests/lifecycle_trace_heap.rs, which measures this shape at 0 surviving bytes.
// Must not be flagged: the buffer is sized before anything is written into it.
use secure_gate::{dynamic_newtype, RevealSecret};

dynamic_newtype!(pub Tok, Vec<u8>, "A token-shaped secret.");
dynamic_newtype!(pub Pw, String, "A password-shaped secret.");

const PAYLOAD: u8 = 0xD7;

pub fn build_token(size: usize) -> Tok {
    Tok::new_with(|v| {
        v.reserve_exact(size);
        v.extend(std::iter::repeat_n(PAYLOAD, size));
    })
}

pub fn build_password(size: usize) -> Pw {
    Pw::new_with(|s| {
        s.reserve_exact(size);
        s.extend(std::iter::repeat_n('q', size));
    })
}
