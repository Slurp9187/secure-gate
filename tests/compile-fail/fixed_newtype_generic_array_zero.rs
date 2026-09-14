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
//! Both a bare declaration and the full doc-plus-`derive:` tail are pinned. The array
//! arm is a single arm with optional groups rather than four arms — it has to be, since
//! the pattern consumes a `:ty` fragment for the element type — so a regression that
//! splits it would take the guard with it on every tail but one.
use secure_gate::fixed_newtype;

fixed_newtype!(pub ZeroPoly, generic [i16; 0]);
fixed_newtype!(pub ZeroPolyDoc, generic [i16; 0], "a zero-length polynomial");
fixed_newtype!(pub ZeroPolyDerive, generic [i16; 0], derive: [IntoWrapper]);
fixed_newtype!(
    pub ZeroPolyBoth,
    generic [u32; 0],
    "doc and derive",
    derive: [FromWrapper]
);

fn main() {}
