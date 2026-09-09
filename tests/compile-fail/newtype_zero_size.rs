//! `fixed_newtype!` must reject `N = 0`, matching `fixed_alias!`'s guard.
//!
//! A zero-byte secret is valid Rust but has no cryptographic utility; the
//! guard is the same `[(); $size][0]` const-eval trick the alias macro uses,
//! so both produce the identical diagnostic.
use secure_gate::fixed_newtype;

fixed_newtype!(pub Bad, 0);

fn main() {}
