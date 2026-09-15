#![cfg_attr(not(feature = "alloc"), no_std)]
use secure_gate::{fixed_newtype, RevealSecret, SecretLen};
fixed_newtype!(pub NoStdKey, 16);

// The `generic` arm exists for exactly this target: with no allocator there is no
// `Dynamic`, so `Fixed` is the only wrapper, and a secret here is often not a byte
// array. `[i16; 256]` is an ML-KEM secret polynomial.
fixed_newtype!(pub Poly, generic [i16; 256]);
#[test]
fn t() {
    let k = NoStdKey::new([3u8; 16]);
    let k2 = NoStdKey::new_with(|b| b[0] = 1);
    assert_eq!((k.len(), k2.expose_secret()[0]), (16, 1));
}

// `try_new_with` is forwarded outside every `__sg_if_*!` relay, like `new_with`, so it
// must resolve with no features at all. That matters more here than for most of this
// surface: on a target with no allocator, `Fixed` is the only wrapper there is, and
// filling one from a fallible source (a hardware RNG, a flash read) is the ordinary
// case rather than an exotic one. Both arms are named — the size-literal and the
// `generic` one — because they are separate emissions and a regression could drop
// either alone.
#[test]
fn try_new_with_is_forwarded_without_alloc() {
    let k = NoStdKey::try_new_with(|b| {
        b[0] = 9;
        Ok::<(), ()>(())
    })
    .expect("ok");
    assert_eq!(k.expose_secret()[0], 9);

    let p = Poly::try_new_with(|c| {
        c[0] = -1;
        Ok::<(), ()>(())
    })
    .expect("ok");
    assert_eq!(p.expose_secret()[0], -1);

    assert!(NoStdKey::try_new_with(|_| Err::<(), ()>(())).is_err());
}

// The Base32 decode constructor is forwarded *outside* `__sg_if_alloc!`, so a
// newtype exposes it whether or not `alloc` is on. This pins that forwarding.
// It does NOT exercise the alloc-free code path: libtest needs `std`, so this test
// only ever runs with `alloc` present. The no-alloc body of `try_from_base32` is
// compiled only by the `thumbv7em-none-eabihf` cross-build. (The bech32 test below
// is different: CI runs it under `--no-default-features --features encoding-bech32`,
// where the crate itself is built without `alloc`.)
#[cfg(feature = "encoding-base32")]
#[test]
fn base32_decode_constructor_is_forwarded() {
    let k = NoStdKey::try_from_base32("VOV2XK5LVOV2XK5LVOV2XK5LVM").unwrap();
    assert_eq!(k.expose_secret(), &[0xABu8; 16]);
    // Strictness still holds on the no-alloc path: lowercase is rejected.
    assert!(NoStdKey::try_from_base32("vov2xk5lvov2xk5lvov2xk5lvm").is_err());
}

// Audit finding 1: `Fixed::try_from_bech32*` is alloc-free, and `fixed_newtype!`
// forwards the bech32m decoders outside `__sg_if_alloc!` — but the bech32 ones were
// inside it. A no-alloc newtype could decode BIP-350 and not BIP-173.
#[cfg(all(feature = "encoding-bech32", not(feature = "alloc")))]
#[test]
fn nostd_newtype_decodes_both_checksums() {
    secure_gate::fixed_newtype!(pub NoAllocKey, 4);
    // Both must exist without `alloc`; the payload is irrelevant, resolution is the test.
    const S: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    // All EIGHT are named on purpose. The `_sized` four are the ones #171 dropped, and
    // they live in the same `impl` block as the plain four -- so naming only the plain
    // ones would let a future split re-introduce exactly the bug this test exists for.
    let _ = NoAllocKey::try_from_bech32(S, "bc");
    let _ = NoAllocKey::try_from_bech32_unchecked(S);
    let _ = NoAllocKey::try_from_bech32_sized::<2048>(S, "bc");
    let _ = NoAllocKey::try_from_bech32_unchecked_sized::<2048>(S);
    let _ = NoAllocKey::try_from_bech32m(S, "bc");
    let _ = NoAllocKey::try_from_bech32m_unchecked(S);
    let _ = NoAllocKey::try_from_bech32m_sized::<2048>(S, "bc");
    let _ = NoAllocKey::try_from_bech32m_unchecked_sized::<2048>(S);
}

// `Poly` gets access, redaction, zeroization — and, because `[i16; 256]` is an array
// the macro can see the shape of, `SecretLen` too. The old objection to forwarding it
// was that "a length in elements is not the byte length callers expect"; the answer is
// that `SecretLen` has both, and `Fixed<[T; N]>` already computes both correctly. What
// stays absent is the encoders: hex over `[i16]` has no defined byte order.
#[test]
fn generic_arm_wraps_a_non_byte_array() {
    let p = Poly::new([0i16; 256]);
    assert_eq!(p.with_secret(|c| c.len()), 256);
    let q = Poly::new_with(|c| c.fill(1));
    assert_eq!(q.with_secret(|c| c[0]), 1);
    // `#[repr(transparent)]` over `Fixed<[i16; 256]>`: 256 coefficients, 2 bytes each.
    assert_eq!(core::mem::size_of::<Poly>(), 512);
}

// The array arm's own `len()`, with no `IntoWrapper` and no trip through `with_secret`.
// The two answers differ for a non-byte element type, which is the whole reason the
// element-count objection did not survive: both questions have an answer and they are
// not the same number.
#[test]
fn the_array_arm_forwards_secret_len_in_both_units() {
    let p = Poly::new([0i16; 256]);
    assert_eq!((p.len(), p.byte_len()), (256, 512));
    assert!(!p.is_empty());
}
