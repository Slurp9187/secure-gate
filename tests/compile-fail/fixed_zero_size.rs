//! A secret of zero size cannot be constructed, however it is spelled.
//!
//! A zero-length secret has nothing to protect, and it fails silently rather than
//! loudly: it constructs, reports `len() == 0`, still prints `[REDACTED]`, encodes to
//! `""`, and compares `ct_eq`-equal to any other empty. The guard is a `const` assertion
//! in `Fixed::new` and `Fixed::new_with`, the two bodies every other constructor funnels
//! through, so all three constructions below are rejected: the byte array, the scoped
//! constructor, and a newtype over a zero-sized inner type via the `generic` arm. Only
//! two diagnostics appear, because the third routes through `Fixed::<[u8; 0]>::new` as
//! well and a failed constant is reported once.
//!
//! The error is post-monomorphization, so it fires here at the construction rather than
//! where the type was named — `type Name = Fixed<[u8; 0]>;` on its own still compiles —
//! and it is raised during codegen, so `cargo check` does not see it. That is why the
//! companion `pass` case in `tests/compile-pass/` exists: it puts `trybuild` into
//! `cargo build` mode, without which this file compiles clean.
//!
//! Note also what this file is: a binary, with a `main`. That is what makes these
//! constructions codegen roots and so reachable by the guard. The same constructions placed
//! behind a non-generic `#[inline]` function in a *library* are not roots and do not fire
//! until a downstream crate instantiates them — see the `# Zero-size` section on `Fixed`.
use secure_gate::{Fixed, fixed_newtype};

fixed_newtype!(pub ZeroSized, generic [u8; 0]);

fn main() {
    let _ = Fixed::new([0u8; 0]);
    let _ = Fixed::<[u8; 0]>::new_with(|_| {});
    let _ = ZeroSized::new([]);
}
