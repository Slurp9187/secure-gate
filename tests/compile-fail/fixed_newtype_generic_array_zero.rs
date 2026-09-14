//! The array arm rejects `N = 0` at the declaration, like the size-literal arm.
//!
//! `generic [i16; 0]` used to be caught only by `Fixed`'s construction-time guard, a
//! post-monomorphization error that `cargo check` cannot see and that a library can
//! publish green when the construction sits behind an `#[inline]` function. Once the
//! element type and the length are both visible as tokens there is no reason to wait:
//! the array arm emits the same `const _: () = { let _ = [(); N][0]; };` courtesy the
//! size-literal arm has always carried, so the error lands on the line that declares
//! the type.
//!
//! All four tails are pinned. The array arm is a single arm with optional groups rather
//! than four arms — it has to be, since the pattern consumes a `:ty` fragment for the
//! element type — so a regression that splits it would take the guard with it on every
//! tail but one.
//!
//! The element type is `i8` and not the `i16` of a real polynomial, because an element
//! wider than a byte would pin the wrong diagnostic. `Fixed<[i16; 0]>` is zero-sized with
//! alignment 2, and a zero-sized field whose alignment is not 1 violates
//! `#[repr(transparent)]`, which every newtype carries — so on some toolchains **E0691**
//! is reported instead of the `E0080` this file is about, and which one wins is a
//! property of the compiler rather than of the guard. An alignment-1 element keeps the
//! snapshot stable and keeps it about the length check. `u8` is unavailable here for a
//! different reason: `generic [u8; N]` is refused one arm earlier as a dominated
//! spelling.
use secure_gate::fixed_newtype;

fixed_newtype!(pub ZeroPoly, generic [i8; 0]);
fixed_newtype!(pub ZeroPolyDoc, generic [i8; 0], "a zero-length polynomial");
fixed_newtype!(pub ZeroPolyDerive, generic [i8; 0], derive: [IntoWrapper]);
fixed_newtype!(
    pub ZeroPolyBoth,
    generic [bool; 0],
    "doc and derive",
    derive: [FromWrapper]
);

fn main() {}
