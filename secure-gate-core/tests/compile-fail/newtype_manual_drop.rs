//! A user-added `Drop` on a generated newtype breaks `into_inner`.
//!
//! No `Drop` is needed — the wrapped `Fixed`/`Dynamic` still runs its own, so
//! zeroization is unaffected — but adding one makes the field unmovable
//! (E0509) and silently costs the tier-3 consumption API. Documented as a
//! trap; pinned here so the diagnostic does not regress.
use secure_gate::fixed_newtype;

fixed_newtype!(pub EncKey, 32);

impl Drop for EncKey {
    fn drop(&mut self) {}
}

fn main() {}
