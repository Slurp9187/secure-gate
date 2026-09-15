//! The secret-copying forms compile. That is the hazard, and this file pins it.
//!
//! A test that demonstrates a leak looks strange until you see what it guards. SECURITY.md
//! §4 makes two claims with opposite signs: that moving a secret out of a reveal borrow is
//! a compile error for a non-`Copy` inner type, and that *copying* one out is not. The
//! first is pinned by `tests/compile-fail/with_secret_no_move_out.rs`. Without this file
//! the second is prose, and prose about what a compiler permits is exactly the kind of
//! claim that rots silently — a future `Deref` removal or an inner-type change could make
//! these stop compiling, and the document would then be scaring readers about something
//! the compiler already handles.
//!
//! The scoping matters because consumers act on it. Reading "the borrow checker protects
//! `Dynamic`" as covering every form retires an audit for the wrapper most likely to hold
//! bulk plaintext, and the form it does *not* cover is the one no grep can find.
//!
//! Each test asserts the copy is real: it outlives the closure, and it is independent of
//! the wrapper's storage.

#![cfg(feature = "alloc")]

use secure_gate::{Dynamic, Fixed, RevealSecret};

/// `Vec::to_vec` copies *through* the shared borrow rather than moving out of it, so
/// `E0507` never fires. This is the form with no operator to grep for.
#[test]
fn dynamic_vec_copies_out_via_to_vec() {
    let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![0xAB; 32]);

    let escaped: Vec<u8> = secret.with_secret(|b| b.to_vec());

    // It outlived the closure, and it is the secret.
    assert_eq!(escaped.len(), 32);
    assert!(escaped.iter().all(|&b| b == 0xAB));

    // It is an independent allocation: nothing the wrapper does will wipe it, and
    // nothing done to it reaches the wrapper.
    let wrapper_ptr = secret.with_secret(|b| b.as_ptr());
    assert_ne!(
        escaped.as_ptr(),
        wrapper_ptr,
        "copy shares the wrapper's buffer"
    );
}

/// `clone` is the same shape wearing a more obvious name.
#[test]
fn dynamic_vec_copies_out_via_clone() {
    let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![0xCD; 16]);
    let escaped: Vec<u8> = secret.with_secret(|b| b.clone());
    assert_eq!(escaped, vec![0xCD; 16]);
}

/// `Dynamic<String>` is not protected either. `to_string` goes through `Display`, so
/// there is no `clone`, no `*`, and no `to_vec` for a reader to notice.
#[test]
fn dynamic_string_copies_out_via_to_string() {
    let secret: Dynamic<String> = Dynamic::new(String::from("correct horse"));
    let escaped: String = secret.with_secret(|s| s.to_string());
    assert_eq!(escaped, "correct horse");
}

/// The deref form on `Copy` storage: an owned array on the stack, nothing to wipe it.
#[test]
fn fixed_array_copies_out_via_deref() {
    let secret: Fixed<[u8; 32]> = Fixed::new([0xEF; 32]);

    let escaped: [u8; 32] = secret.with_secret(|p| *p);
    assert_eq!(escaped, [0xEF; 32]);

    // The pattern-binding spelling is the same defect with no `*` in the source.
    let escaped2: [u8; 32] = secret.with_secret(|&p| p);
    assert_eq!(escaped2, [0xEF; 32]);
}

/// `FixedStorage` covers far more than `[T; N]`, and the list does not partition by
/// hazard: these leak exactly like a byte array, while `Fixed<Fixed<_>>` and
/// `Fixed<Zeroizing<_>>` cannot (they have destructors, so they cannot be `Copy`).
/// `Copy` is the discriminator — not the shape of the storage type.
#[test]
fn non_array_copy_storage_leaks_identically() {
    let pair: Fixed<(u64, u64)> = Fixed::new((0x1122_3344_5566_7788, 0x99AA_BBCC_DDEE_FF00));
    let escaped_pair: (u64, u64) = pair.with_secret(|p| *p);
    assert_eq!(escaped_pair.0, 0x1122_3344_5566_7788);

    let opt: Fixed<Option<[u8; 32]>> = Fixed::new(Some([7u8; 32]));
    let escaped_opt: Option<[u8; 32]> = opt.with_secret(|p| *p);
    assert_eq!(escaped_opt, Some([7u8; 32]));

    let wrapping: Fixed<core::num::Wrapping<u64>> = Fixed::new(core::num::Wrapping(0xDEAD_BEEF));
    let escaped_w: core::num::Wrapping<u64> = wrapping.with_secret(|p| *p);
    assert_eq!(escaped_w.0, 0xDEAD_BEEF);
}

/// The shape that does not leak: copy wrapper-to-wrapper, so the bytes never exist
/// outside a type that wipes them. This is what SECURITY.md §4 recommends.
#[test]
fn wrapper_to_wrapper_copy_does_not_escape() {
    let src: Fixed<[u8; 32]> = Fixed::new([0x5A; 32]);
    let mut dst: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);

    src.with_secret(|s| {
        secure_gate::RevealSecretMut::with_secret_mut(&mut dst, |d| d.copy_from_slice(s))
    });

    assert!(dst.with_secret(|d| d.iter().all(|&b| b == 0x5A)));
}
