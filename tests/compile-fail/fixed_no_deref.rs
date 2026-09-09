//! `Fixed<T>` must not implement `Deref` or `AsRef`.
//!
//! While a secret is held, the only way to it is `RevealSecret` / `RevealSecretMut`.
//! This is the load-bearing "no implicit access" claim, so it is enforced here rather
//! than only asserted in prose. `into_inner()` returns a plain `T`, which derefs only
//! if `T` itself does. The one type in this crate that derefs by design is
//! `EncodedSecret`, the wrapper the encoders return — see "Where accident-prevention
//! ends" in the crate docs. This test pins the boundary, not a blanket ban on `Deref`.

use secure_gate::Fixed;

fn takes_inner_ref(_: &[u8; 4]) {}

fn main() {
    let secret: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);

    // 1. No `Deref`: `*secret` must not reach the inner array.
    let _via_deref: [u8; 4] = *secret;

    // 2. No `AsRef`: `.as_ref()` must not reach the inner array.
    let _via_as_ref: &[u8; 4] = secret.as_ref();

    // 3. No deref coercion at a call site that wants `&[u8; 4]`.
    takes_inner_ref(&secret);
}
