//! macros_suite/newtype_generic_ct_eq.rs — `derive: [ConstantTimeEq]` on a `generic` arm.
//!
//! The shaped arms (`fixed_newtype!(.., N)`, `dynamic_newtype!(.., String | Vec<u8>)`)
//! emit `ConstantTimeEq` themselves, so naming the token there is `E0119`. The `generic`
//! arms cannot: an arbitrary inner type may or may not implement the trait, and nothing
//! readable off the tokens decides it. There the token stays a genuine opt-in.
//!
//! Until this file existed that opt-in had no coverage at all — every declaration in the
//! suite used a shaped arm. It is the only path by which a caller's own constant-time type
//! reaches the newtype, so it is pinned here rather than left to the first person who tries.

use secure_gate::{ConstantTimeEq, FixedStorage, RevealSecret, SentinelValue, fixed_newtype};

/// A caller-defined payload with its own constant-time comparison.
///
/// Three of the four impls below are what `Fixed` requires of *any* custom inner type —
/// only `ConstantTimeEq` is specific to this test.
#[derive(Default)]
pub struct Tag8([u8; 8]);

impl secure_gate::__private::Zeroize for Tag8 {
    fn zeroize(&mut self) {
        secure_gate::__private::Zeroize::zeroize(&mut self.0);
    }
}

impl FixedStorage for Tag8 {}

impl SentinelValue for Tag8 {
    fn sentinel_value() -> Self {
        Tag8([0u8; 8])
    }
}

impl ConstantTimeEq for Tag8 {
    fn ct_eq(&self, other: &Self) -> bool {
        ConstantTimeEq::ct_eq(&self.0, &other.0)
    }
}

fixed_newtype!(pub TagNt, generic Tag8, derive: [ConstantTimeEq]);

// The same inner type without the token: the opt-in is what forwards `ct_eq`, so this
// newtype deliberately does not have it. If the `generic` arm ever started emitting the
// impl automatically, this declaration and `TagNt` would collide at `E0119` and the
// suite would fail rather than quietly widening the guarantee.
fixed_newtype!(pub TagPlain, generic Tag8);

#[test]
fn generic_arm_forwards_the_callers_ct_eq() {
    let a = TagNt::new(Tag8([1u8; 8]));
    let b = TagNt::new(Tag8([1u8; 8]));
    let c = TagNt::new(Tag8([2u8; 8]));

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}

#[test]
fn the_opt_in_is_the_only_thing_that_differs() {
    // `TagPlain` is the same payload declared without the token. It still has the
    // reduced generic surface — this pins that the opt-in adds `ct_eq` and nothing else.
    let p = TagPlain::new(Tag8([9u8; 8]));
    assert_eq!(p.with_secret(|t| t.0[0]), 9);
}
