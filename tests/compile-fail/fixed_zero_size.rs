//! A secret of zero size cannot be constructed, however it is spelled.
//!
//! A zero-length secret has nothing to protect, and it fails silently rather than
//! loudly: it constructs, reports `len() == 0`, still prints `[REDACTED]`, encodes to
//! `""`, and compares `ct_eq`-equal to any other empty. The guard is a `const` assertion
//! in `Fixed::new` and `Fixed::new_with`, the two bodies every other constructor funnels
//! through, so all three constructions below are rejected: the byte array, the scoped
//! constructor, and a newtype over a zero-sized inner type via the `generic` arm.
//!
//! Finding a spelling for that third case is harder than it looks, because two other
//! guards now stand in front of this one. `generic [u8; 0]` is a declaration-site
//! `compile_error!` (dominated by the size-literal arm), and `generic [i16; 0]` is a
//! declaration-site `E0080` from the array arm's `[(); N][0]` check — neither ever
//! reaches construction. `generic [(); 4]` threads between them: `N = 4` satisfies the
//! declaration-site guard, while `size_of::<[(); 4]>()` is still 0, so the construction
//! guard is what catches it. That is the property worth pinning here — the early guard
//! narrows the ways in, it does not replace the one that fires at construction.
//!
//! Two `E0080`s appear: `Fixed<[u8; 0]>` from `new` in `main` (with a second "erroneous
//! constant" note for the `new_with` line, which reads the same `NON_ZERO_SIZED`), and
//! `Fixed<[(); 4]>` from the generated `const fn new`, whose span is the macro
//! invocation.
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

fixed_newtype!(pub ZeroSized, generic [(); 4]);

fn main() {
    let _ = Fixed::new([0u8; 0]);
    let _ = Fixed::<[u8; 0]>::new_with(|_| {});
    let _ = ZeroSized::new([(); 4]);
}
