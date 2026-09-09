//! R3: a newtype must not `Deref` to its base wrapper.
//!
//! Deref coercion would let `&PublicId` be passed anywhere a
//! `&Dynamic<String>` is expected, returning it to the synonym pool at every
//! call site — the same failure as an implicit `From`, by another route.
use secure_gate::{Dynamic, dynamic_newtype};

dynamic_newtype!(pub PublicId, String);

fn takes_base(_: &Dynamic<String>) {}

fn main() {
    let p = PublicId::new("x");
    let _via_deref: &Dynamic<String> = &*p;
    takes_base(&p);
}
