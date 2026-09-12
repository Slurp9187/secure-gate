//! Positive control for the zero-size guard, and the reason it can be tested at all.
//!
//! Two jobs. First, it pins that the guard rejects *only* what it should: every
//! construction below is a legitimate non-zero secret and must keep compiling, through
//! `new`, through the scoped `new_with`, through a generic function, and through a
//! newtype over a non-byte inner type.
//!
//! Second, it is what makes the companion `compile-fail` case observable. The guard is a
//! post-monomorphization `const` error, so it fires during codegen and `cargo check` does
//! not see it; `trybuild` runs `cargo check` unless a `pass` case is present, in which
//! case it runs `cargo build`. This file is that `pass` case.
use secure_gate::{Fixed, RevealSecret, fixed_newtype};

fixed_newtype!(pub Poly, generic [i16; 4]);

fn generic_construct<const N: usize>(byte: u8) -> Fixed<[u8; N]> {
    Fixed::new([byte; N])
}

fn main() {
    let a = Fixed::new([1u8; 32]);
    assert_eq!(a.expose_secret()[0], 1);

    let b = Fixed::<[u8; 4]>::new_with(|arr| arr.fill(2));
    assert_eq!(b.expose_secret(), &[2u8; 4]);

    let c = generic_construct::<16>(3);
    assert_eq!(c.expose_secret()[0], 3);

    let d = Poly::new([4i16; 4]);
    assert_eq!(d.with_secret(|p| p[0]), 4);
}
