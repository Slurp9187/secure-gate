// ==========================================================================
// tests/encoding/bech32_tests.rs
// ==========================================================================
// Tests for bech32 encoding.

#![cfg(test)]

use secure_gate::encoding::bech32::Bech32String;

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32string_new_rejects_invalid() {
    // Invalid HRP
    let s = "invalid1data".to_string();
    let err = Bech32String::new(s).unwrap_err();
    assert_eq!(err, "invalid bech32 string");

    // Invalid bech32
    let s = "age_invalid".to_string();
    let err = Bech32String::new(s).unwrap_err();
    assert_eq!(err, "invalid bech32 string");

    // Invalid characters
    let s = "age!invalid".to_string();
    let err = Bech32String::new(s).unwrap_err();
    assert_eq!(err, "invalid bech32 string");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32string_empty_fails() {
    let err = Bech32String::new("".to_string()).unwrap_err();
    assert_eq!(err, "invalid bech32 string");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32string_accepts_generic_hrp() {
    // Valid bech32 with non-age HRP should now be accepted (generic support)
    let s = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(); // bitcoin
    let bech32 = Bech32String::new(s).unwrap();
    assert!(bech32.is_bech32());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32string_accepts_various_valid_bech32() {
    // Test valid Bech32 strings with various HRPs (now accepted generically)
    let valid_strings = [
        "A12UEL5L",  // HRP: "a"
        "a12uel5l",  // HRP: "a" lowercase
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",  // HRP: "an83..."
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",  // HRP: "abcdef1"
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",  // bitcoin
    ];

    for s in valid_strings {
        let bech32 = Bech32String::new(s.to_string()).unwrap();
        assert!(bech32.is_bech32(), "Failed to accept: {}", s);
    }
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
#[test]
fn bech32string_accepts_bech32m_from_rng() {
    // Test that Bech32String::new() accepts a Bech32m string generated from RNG
    use secure_gate::random::FixedRng;
    let rng = FixedRng::<32>::generate();
    let bech32m_str = rng.to_bech32m("test").expose_secret().clone();
    let bech32 = Bech32String::new(bech32m_str).unwrap();
    // Note: variant is Bech32 due to crate limitations, but data round-trips correctly
    assert_eq!(
        bech32.decode_secret_to_bytes(),
        rng.expose_secret().to_vec()
    );
}

#[cfg(all(feature = "encoding-bech32", feature = "rand"))]
#[test]
fn rng_bech32_integration() {
    use secure_gate::random::FixedRng;
    let rng1 = FixedRng::<32>::generate();
    let b32 = rng1.into_bech32("example");
    assert!(b32.is_bech32());
    assert_eq!(b32.decode_secret_to_bytes().len(), 32);

    let rng2 = FixedRng::<32>::generate();
    let b32m = rng2.into_bech32m("example");
    assert!(b32m.is_bech32m());
    assert_eq!(b32m.decode_secret_to_bytes().len(), 32);
}
