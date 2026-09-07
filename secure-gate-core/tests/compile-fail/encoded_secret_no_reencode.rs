//! An `EncodedSecret` must not be accepted by the crate's own encoder traits.
//!
//! `EncodedSecret` derefs to `str`, and `str: AsRef<[u8]>`. While the encode traits were
//! blanket-implemented for `AsRef<[u8]>` alone, method resolution therefore accepted an
//! already-encoded secret as an encoding *input*: `encoded.to_hex()` compiled and
//! hex-encoded the encoded text rather than the secret, returning 124 characters for a
//! 32-byte key. Nothing in the name or the signature suggested it.
//!
//! The `EncodableBytes` bound closes it. Legitimate reads are untouched — `Deref` still
//! gives `&*encoded`, `&str` coercion, and every inherent `str` method.

use secure_gate::{Fixed, ToHex};

fn main() {
    let encoded = Fixed::new([0xABu8; 32]).to_hex_zeroizing();

    // Must not compile: this would hex-encode the hex string.
    let _double = encoded.to_hex();
}
