//! `EncodedSecret` deliberately implements no `PartialEq`.
//!
//! Comparing secret material with `==` is variable-time: the derived implementation
//! short-circuits on the first differing byte, which is exactly the leak
//! [`ConstantTimeEq`] exists to avoid. An encoded secret is the whole secret in a
//! longer alphabet, so it inherits that rule.
//!
//! The type's contract is "redacted `Debug`, `Deref`, no `Display`, no `PartialEq`,
//! no `AsRef`". The first four were pinned by tests; this file pins the fifth, so a
//! future `#[derive(PartialEq)]` added for convenience fails the suite instead of
//! quietly restoring a timing side channel.
//!
//! Reading the value out and comparing that is still possible — `&*a == &*b` compares
//! two `&str`. That is a deliberate, visible choice at the call site, which is the
//! whole point of not having the operator on the wrapper.

use secure_gate::{Fixed, ToHex};

fn main() {
    let a = Fixed::new([0xABu8; 32]).to_hex();
    let b = Fixed::new([0xCDu8; 32]).to_hex();

    // Must not compile: no `PartialEq` on `EncodedSecret`.
    let _same = a == b;
}
