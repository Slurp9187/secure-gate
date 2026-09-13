//! Class 5 — the secret bytes end up in a buffer that never passed through the wrapper's `&mut`.
//!
//! Nothing here needs a growth-capable operation to reach an unwiped buffer. The wrapper is used
//! exactly as documented and still wipes everything it owns; the residue is in memory it never
//! owned.
//!
//! * `rotate_tail` calls `split_off`, which is a *shrink*. The returned `Vec<u8>` is a plain value
//!   with no `Drop` that wipes, and it carries half the secret out of the wrapper by design.
//! * `absorb_staging` hands a donor `Vec` to `append`. `Vec::append` copies the elements out and
//!   sets the donor's length to 0 — the donor keeps its allocation, with the bytes still in it.
//! * `from_json` is the `Deserialize` success path. The `Dynamic` that comes back is correct and
//!   wipes itself; the buffers `serde_json`'s visitor grew on the way there are already gone.

use secure_gate::RevealSecretMut;

use super::roles::SessionToken;

/// Splits a token in half and returns the tail for the next epoch.
///
/// The wrapper keeps the head and will wipe it. The tail is a bare `Vec<u8>`.
pub fn rotate_tail(tok: &mut SessionToken, at: usize) -> Vec<u8> {
    tok.with_secret_mut(|buf| buf.split_off(at))
}

/// Folds a staging buffer into the token. `staging` is left empty but still allocated.
pub fn absorb_staging(tok: &mut SessionToken, staging: &mut Vec<u8>) {
    tok.with_secret_mut(|buf| buf.append(staging));
}

/// Parses a token from JSON. Ordinary, documented use of `derive: [Deserialize]`-shaped input.
pub fn from_json(json: &str) -> secure_gate::Dynamic<Vec<u8>> {
    serde_json::from_str(json).expect("valid token JSON")
}
