#![cfg_attr(not(feature = "alloc"), no_std)]
use secure_gate::{fixed_newtype, RevealSecret, SecretLen};
fixed_newtype!(pub NoStdKey, 16);
#[test]
fn t() {
    let k = NoStdKey::new([3u8; 16]);
    let k2 = NoStdKey::new_with(|b| b[0] = 1);
    assert_eq!((k.len(), k2.expose_secret()[0]), (16, 1));
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
