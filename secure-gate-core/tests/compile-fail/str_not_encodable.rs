//! Strings are this crate's decoding input, not an encoding input.
//!
//! `str: AsRef<[u8]>`, so an `AsRef<[u8]>`-only blanket made `"text".to_hex()` compile
//! and encode the string's UTF-8 bytes. That is occasionally what someone means and
//! usually not — and it is the same reachability that let an `EncodedSecret` be
//! re-encoded. Say `.as_bytes()` when the UTF-8 is what you actually want.

use secure_gate::ToHex;

fn main() {
    // Must not compile: strings decode, they do not encode.
    let _ = "text".to_hex();
}
