#![cfg_attr(not(feature = "alloc"), no_std)]
use secure_gate::{RevealSecret, SecretLen, fixed_newtype};
fixed_newtype!(pub NoStdKey, 16);
#[test]
fn t() {
    let k = NoStdKey::new([3u8; 16]);
    let k2 = NoStdKey::new_with(|b| b[0] = 1);
    assert_eq!((k.len(), k2.expose_secret()[0]), (16, 1));
}

// The Base32 decode constructor is forwarded *outside* `__sg_if_alloc!`, so a
// newtype exposes it whether or not `alloc` is on. This pins that forwarding.
// It does NOT exercise the alloc-free code path: libtest needs `std`, so every
// configuration that runs this file has `alloc`. The no-alloc body of
// `try_from_base32` is compiled only by the `thumbv7em-none-eabihf` cross-build.
#[cfg(feature = "encoding-base32")]
#[test]
fn base32_decode_constructor_is_forwarded() {
    let k = NoStdKey::try_from_base32("VOV2XK5LVOV2XK5LVOV2XK5LVM").unwrap();
    assert_eq!(k.expose_secret(), &[0xABu8; 16]);
    // Strictness still holds on the no-alloc path: lowercase is rejected.
    assert!(NoStdKey::try_from_base32("vov2xk5lvov2xk5lvov2xk5lvm").is_err());
}
