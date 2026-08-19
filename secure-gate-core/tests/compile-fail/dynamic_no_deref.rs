//! `Dynamic<T>` must not implement `Deref` or `AsRef`.
//!
//! Companion to `fixed_no_deref.rs`; see that file for why the boundary is enforced
//! here and not only in prose.

use secure_gate::Dynamic;

fn takes_inner_ref(_: &Vec<u8>) {}

fn main() {
    let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3, 4]);

    // 1. No `Deref`: `*secret` must not reach the inner `Vec`.
    let _via_deref: &Vec<u8> = &*secret;

    // 2. No `AsRef`: `.as_ref()` must not reach the inner `Vec`.
    let _via_as_ref: &Vec<u8> = secret.as_ref();

    // 3. No deref coercion at a call site that wants `&Vec<u8>`.
    takes_inner_ref(&secret);
}
