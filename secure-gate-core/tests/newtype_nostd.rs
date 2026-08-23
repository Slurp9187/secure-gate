#![cfg_attr(not(feature = "alloc"), no_std)]
use secure_gate::{RevealSecret, SecretLen, fixed_newtype};
fixed_newtype!(pub NoStdKey, 16);
#[test]
fn t() {
    let k = NoStdKey::new([3u8; 16]);
    let k2 = NoStdKey::new_with(|b| b[0] = 1);
    assert_eq!((k.len(), k2.expose_secret()[0]), (16, 1));
}
