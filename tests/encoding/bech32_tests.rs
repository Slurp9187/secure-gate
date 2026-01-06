// Comprehensive tests for Bech32String (both Bech32 and Bech32m variants).
// Ensures validation, normalization, variant detection, and round-tripping.

#![cfg(test)]

use secure_gate::encoding::bech32::Bech32String;

#[cfg(feature = "encoding-bech32")]
#[test]
fn rejects_invalid_strings() {
    let invalid = [
        "",
        "invalid1data",
        "age!invalid",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // wrong checksum
        "abc14w46h2at4w46h2at4w46h2at4w46h2at958ngx", // wrong Bech32m checksum
    ];

    for s in invalid {
        assert_eq!(
            Bech32String::new(s.to_string()).unwrap_err(),
            "invalid bech32 string",
            "Should reject: {}",
            s
        );
    }
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn generic_hrp_support() {
    let various = [
        "A12UEL5L",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    ];

    for s in various {
        let bech32 = Bech32String::new(s.to_string()).unwrap();
        assert!(bech32.is_bech32(), "Failed for Bech32: {}", s);
    }
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
#[test]
fn rng_into_bech32_variant_detection_and_round_trip() {
    use secure_gate::random::FixedRng;

    let rng = FixedRng::<16>::generate();
    let raw_bytes = rng.expose_secret().to_vec();

    let b32 = rng.to_bech32("test");
    let parsed = Bech32String::new(b32.expose_secret().clone()).unwrap();
    assert!(parsed.is_bech32());
    assert_eq!(parsed.decode_secret_to_bytes(), raw_bytes);

    let rng_m = FixedRng::<16>::generate();
    let raw_bytes_m = rng_m.expose_secret().to_vec();

    let b32m = rng_m.to_bech32m("test");
    let parsed_m = Bech32String::new(b32m.expose_secret().clone()).unwrap();
    assert!(parsed_m.is_bech32m());
    assert_eq!(parsed_m.decode_secret_to_bytes(), raw_bytes_m);
}

#[cfg(all(feature = "rand", feature = "encoding-bech32"))]
#[test]
fn rng_into_bech32_consuming_round_trip() {
    use secure_gate::random::FixedRng;

    let rng = FixedRng::<32>::generate();
    let raw_bytes = rng.expose_secret().to_vec();

    let b32 = rng.into_bech32("example");
    assert!(b32.is_bech32());
    assert_eq!(b32.byte_len(), 32);
    assert_eq!(b32.decode_secret_to_bytes(), raw_bytes);

    let rng_m = FixedRng::<32>::generate();
    let raw_bytes_m = rng_m.expose_secret().to_vec();

    let b32m = rng_m.into_bech32m("example");
    assert!(b32m.is_bech32m());
    assert_eq!(b32m.byte_len(), 32);
    assert_eq!(b32m.decode_secret_to_bytes(), raw_bytes_m);
}

#[cfg(all(feature = "encoding-bech32", feature = "ct-eq"))]
#[test]
fn constant_time_equality() {
    let s1 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();

    let b1 = Bech32String::new(s1.clone()).unwrap();
    let b2 = Bech32String::new(s1).unwrap();

    assert!(b1 == b2);
}

#[test]
fn accepts_and_normalizes_valid_bech32m() {
    // Safe, confirmed valid Bech32m vectors (avoiding overly long HRP that triggers parse errors in some contexts)
    let vectors = [
        ("A1LQFN3A", "a1lqfn3a"),
        (
            "ABCDEF1L7AUM6ECHK45NJ3S0WDVT2FG8X9YRZPQZD3RYX",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        ),
        (
            "SPLIT1CHECKUPSTAGEHANDSHAKEUPSTREAMERRANTERREDCAPERREDLC445V",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        ),
    ];

    for (mixed, expected_lower) in vectors {
        let mixed_case = mixed.to_string();
        let bech32 = Bech32String::new(mixed_case).unwrap();

        assert_eq!(bech32.expose_secret(), expected_lower);
        assert!(!bech32.is_bech32());
        assert!(
            bech32.is_bech32m(),
            "Failed variant detection for: {}",
            expected_lower
        );
    }

    // Taproot Bech32m (real-world, witness version 1)
    let taproot_mixed =
        "BC1P0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQZK5JJ0".to_string();
    let taproot_lower = taproot_mixed.to_ascii_lowercase();

    let bech32m = Bech32String::new(taproot_mixed).unwrap();

    assert_eq!(bech32m.expose_secret(), &taproot_lower);
    assert!(bech32m.is_bech32m());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn accepts_and_normalizes_valid_bech32() {
    let mixed_case = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".to_string();
    let expected_lower = mixed_case.to_ascii_lowercase();

    let bech32 = Bech32String::new(mixed_case).unwrap();

    assert_eq!(bech32.expose_secret(), &expected_lower);
    assert!(bech32.is_bech32());
    assert!(!bech32.is_bech32m());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn metadata_methods() {
    let s = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
    let bech32 = Bech32String::new(s).unwrap();

    assert_eq!(bech32.len(), 42);
    assert!(!bech32.is_empty());
    assert_eq!(bech32.byte_len(), 20);
}
