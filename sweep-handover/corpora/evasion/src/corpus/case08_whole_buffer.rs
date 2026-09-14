//! Class 8 — whole-buffer replacement with no capacity change.
//!
//! `SECURITY.md` offers "keep mutations capacity-stable" as one mitigation for reallocation residue.
//! These functions are capacity-stable by that reading — `capacity()` is identical before and after
//! — and still abandon a buffer holding the entire secret, because the buffer is *replaced* rather
//! than resized. A check built around capacity changes has nothing to look at.
//!
//! `fold_case` is the control: `*text =` is a spelling a sweep can match. `normalize` and
//! `fold_case_indirect` put the same assignment one function away, in a module that mentions no
//! secret type.

use secure_gate::RevealSecretMut;

use super::roles::{Passphrase, SessionToken};

/// Rebuilds the buffer from its own contents. Same length, same capacity, different allocation.
pub fn normalize(tok: &mut SessionToken) {
    tok.with_secret_mut(super::util_bits::recode);
}

/// Control: the replacing assignment is at the call site.
pub fn fold_case(pw: &mut Passphrase) {
    pw.with_secret_mut(|text| {
        *text = text.to_uppercase();
    });
}

/// The same replacement, one function away.
pub fn fold_case_indirect(pw: &mut Passphrase) {
    pw.with_secret_mut(super::util_bits::upper);
}
