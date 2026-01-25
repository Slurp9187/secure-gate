#![cfg(all(
    feature = "serde-deserialize",
    any(
        feature = "encoding-hex",
        feature = "encoding-base64",
        feature = "encoding-bech32"
    )
))]

extern crate alloc;

use secure_gate::utilities::decoding::try_decode_any;

#[cfg(all(feature = "encoding-hex", feature = "encoding-base64"))]
#[test]
fn decode_any_prefers_hex_then_base64() {
    // A string that is valid hex and also valid base64url → should pick hex since hex succeeds first
    let ambiguous = "deadbeef"; // valid hex (decodes to [0xde, 0xad, 0xbe, 0xef]), also valid base64url (decodes to different bytes)
    let decoded = try_decode_any(ambiguous).unwrap();
    assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]); // Should be hex decode
}
