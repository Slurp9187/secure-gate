//! The `EncodableBytes` bound must hold for **every** encoder, not just `ToHex`.
//!
//! `encoded_secret_no_reencode.rs` pins the hex case. That one test would keep passing
//! if a later edit restored the bare `AsRef<[u8]>` blanket on any of the other four
//! traits, because nothing else exercises them with a string-shaped input. Each encoder
//! carries the same footgun: `EncodedSecret` derefs to `str`, `str: AsRef<[u8]>`, so
//! without the second bound the already-encoded text is silently accepted as fresh
//! input and encoded again.
//!
//! One file, four call sites, so a regression in any single trait fails the suite.

use secure_gate::{Fixed, ToBase32, ToBase64Url, ToBech32, ToBech32m, ToHex};

fn main() {
    let key = [0xABu8; 32];
    let encoded = Fixed::new(key).to_hex();

    // Every trait above is in scope and works for a byte-shaped source. Exercising
    // them here keeps the imports used: a method call that fails to resolve does not
    // count as a use, and CI builds with `-D warnings`, which would turn the resulting
    // `unused_imports` into an error inside this test's .stderr snapshot.
    let _ = key.to_base32();
    let _ = key.to_base64url();
    let _ = key.try_to_bech32("bc");
    let _ = key.try_to_bech32m("bc");

    // None of these may compile: each would encode the hex text, not the key.
    let _b32 = encoded.to_base32();
    let _b64 = encoded.to_base64url();
    let _bech = encoded.try_to_bech32("bc", secure_gate::Case::Lower);
    let _bechm = encoded.try_to_bech32m("bc", secure_gate::Case::Lower);
}
