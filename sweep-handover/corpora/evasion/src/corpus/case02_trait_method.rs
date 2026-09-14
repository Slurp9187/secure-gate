//! Class 2 — growth through a trait method.
//!
//! Four variants. `stamp_passphrase` is the control for this class: `write!` is on every growth list
//! anyone would write, so a sweep catches it. The other three do the same damage with no listed
//! identifier at the call site:
//!
//! * `soak_token` goes through `Soak::soak`, a trait this consumer defined in `super::util_bits`;
//! * `stamp_passphrase_indirect` is the `write!` moved one function away;
//! * `log_into_token` / `drain_into_token` use `std::io::Write`. `secure-gate` forwards `io::Write` for
//!   `Dynamic<Vec<u8>>` itself, and that forward grows by hand and wipes the old buffer first — but
//!   `<Vec<u8> as io::Write>` is `std`'s impl, and once the consumer holds the `&mut Vec<u8>` that is
//!   the impl that runs.

use std::fmt::Write as _;
use std::io::Write as _;

use secure_gate::RevealSecretMut;

use super::roles::{Passphrase, SessionToken};
use super::util_bits::Soak as _;

/// Growth through a consumer trait method.
pub fn soak_token(tok: &mut SessionToken, material: &[u8]) {
    tok.with_secret_mut(|buf| buf.soak(material));
}

/// Control: `write!` at the call site, where a sweep can see it.
pub fn stamp_passphrase(pw: &mut Passphrase, counter: u32) {
    pw.with_secret_mut(|text| {
        let _ = write!(text, "#{counter}");
    });
}

/// The same `write!`, one function away.
pub fn stamp_passphrase_indirect(pw: &mut Passphrase, counter: u32) {
    pw.with_secret_mut(|text| super::util_bits::stamp(text, counter));
}

/// Growth through `std::io::Write` on the inner `Vec<u8>`, not through the crate's own forward.
/// `write_all` is a nameable token, so this one is the control for the `io::Write` variant.
pub fn log_into_token(tok: &mut SessionToken, record: &[u8]) {
    tok.with_secret_mut(|buf| {
        let _ = buf.write_all(record);
    });
}

/// The same `io::Write` growth with no writing verb at the call site: `io::copy` takes the `&mut
/// Vec<u8>` as a sink and grows it, and `copy` is not a growth operation anywhere else in the world.
pub fn drain_into_token<R: std::io::Read>(tok: &mut SessionToken, src: &mut R) {
    tok.with_secret_mut(|buf| {
        let _ = std::io::copy(src, buf);
    });
}
