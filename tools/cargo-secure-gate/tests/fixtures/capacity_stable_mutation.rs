// Derived from `check_capacity_stable_mutation_stays_in_one_buffer`, measured at
// 0 allocations and 0 surviving bytes. It is the pattern SECURITY.md recommends.
// Must not be flagged by SG002, which owns construction sites only.
use secure_gate::{dynamic_newtype, RevealSecretMut};

dynamic_newtype!(pub Tok, Vec<u8>, "A token-shaped secret.");

const OVERWRITE: u8 = 0x5A;

pub fn rotate_in_place(tok: &mut Tok) {
    tok.with_secret_mut(|v: &mut Vec<u8>| {
        for b in v.iter_mut() {
            *b = OVERWRITE;
        }
    });
}

pub fn truncate_only(tok: &mut Tok, half: usize) {
    tok.with_secret_mut(|v: &mut Vec<u8>| v.truncate(half));
}
