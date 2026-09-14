//! Class 4 — `unsafe { s.as_mut_vec() }` turns `&mut String` into `&mut Vec<u8>`.
//!
//! The crate is `#![forbid(unsafe_code)]`; the consumer is not. This class is the most catchable one
//! in the corpus, because `as_mut_vec` is a single distinctive token: an unconditional grep for it,
//! with no window and no route requirement, flags it. The cost is that such a grep flags every
//! `as_mut_vec` in the repository, secret or not.
//!
//! What that grep cannot do is read code it is not pointed at. `append_via_dep` reaches the same
//! re-borrow through `helpers::bytes_mut`, a path dependency — a stand-in for any of the crates in
//! a consumer's lock file. Nothing in `consumer/src` contains the token.

use secure_gate::RevealSecretMut;

use super::roles::Passphrase;
use super::util_pad;

/// Control: the `unsafe` block and the growth are adjacent, in this repository.
pub fn append_raw(pw: &mut Passphrase, bytes: &[u8]) {
    pw.with_secret_mut(|text| {
        // SAFETY: `bytes` is ASCII in every call below, so UTF-8 stays valid.
        let raw = unsafe { text.as_mut_vec() };
        raw.extend_from_slice(bytes);
    });
}

/// Re-borrow only, still in this repository. The `unsafe` and the growth are now different
/// functions, so a windowed sweep misses it and only the unconditional token grep catches it.
fn borrow_bytes(text: &mut String) -> &mut Vec<u8> {
    // SAFETY: callers append ASCII only.
    unsafe { text.as_mut_vec() }
}

/// The in-repository split version.
pub fn append_via_borrow(pw: &mut Passphrase, bytes: &[u8]) {
    pw.with_secret_mut(|text| util_pad::pad(borrow_bytes(text), bytes));
}

/// The dependency version. `as_mut_vec` appears nowhere in this crate's sources.
pub fn append_via_dep(pw: &mut Passphrase, bytes: &[u8]) {
    pw.with_secret_mut(|text| {
        // SAFETY: callers append ASCII only.
        let raw = unsafe { helpers::bytes_mut(text) };
        helpers::concat(raw, bytes);
    });
}
