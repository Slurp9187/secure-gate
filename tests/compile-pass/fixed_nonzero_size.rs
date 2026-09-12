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
//! It is also the positive control for the `FixedStorage` bound on `Fixed::new`: every
//! shape that bound must keep accepting is built here — a byte array, a non-byte array, a
//! tuple, an `Option`, and a custom inner type that makes the assertion in one line. It
//! stays `alloc`-free on purpose: its test runs under `--no-default-features` too, so the
//! boxed-slice shape is covered by `fixed_storage_accepts_a_boxed_slice` in
//! `tests/core_tests.rs` instead.
use secure_gate::{Fixed, FixedStorage, RevealSecret, SentinelValue, fixed_newtype};
use zeroize::Zeroize;

fixed_newtype!(pub Poly, generic [i16; 4]);

struct CustomKey([u8; 8]);

impl Zeroize for CustomKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl SentinelValue for CustomKey {
    fn sentinel_value() -> Self {
        CustomKey([0u8; 8])
    }
}
// The whole cost of the bound for a custom inner type: one asserted line.
impl FixedStorage for CustomKey {}

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

    let f = Fixed::new(([6u8; 4], 7u32));
    assert_eq!(f.with_secret(|(arr, n)| (arr[0], *n)), (6, 7));

    let h = Fixed::new(Some([9u8; 4]));
    assert_eq!(h.with_secret(|o| o.map(|a| a[0])), Some(9));

    let g = Fixed::new(CustomKey([8u8; 8]));
    assert_eq!(g.with_secret(|k| k.0[0]), 8);
}
