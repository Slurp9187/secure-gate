//! A user-added `Drop` on a generated newtype breaks `into_inner`.
//!
//! No `Drop` is needed — the wrapped `Fixed`/`Dynamic` still runs its own, so
//! zeroization is unaffected — but adding one makes the field unmovable
//! (E0509) and silently costs the tier-3 consumption API. Documented as a
//! trap; pinned here so the diagnostic does not regress.
//!
//! The `generic [T; N]` arm, not a byte size: with `sealed` on, the size arm also
//! emits `FixedRole::into_fixed`, a second move out of the same `Drop` type, so the
//! snapshot would differ between `--features=full` and `--all-features`. This arm
//! carries the same `into_inner` and no `FixedRole`, so every feature set reports
//! the one E0509.
use secure_gate::fixed_newtype;

fixed_newtype!(pub Poly, generic [i16; 4]);

impl Drop for Poly {
    fn drop(&mut self) {}
}

fn main() {}
