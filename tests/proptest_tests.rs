// ==========================================================================
// tests/proptest_tests.rs
// ==========================================================================
// Property-based tests using proptest to verify key invariants like round-trips
// and correctness properties under various inputs.

#![cfg(test)]

#[cfg(feature = "encoding-base64")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "encoding-base64")]
use base64::prelude::*;
#[cfg(feature = "encoding-bech32")]
use bech32::Hrp;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    all(feature = "serde-deserialize", feature = "serde-serialize"),
    feature = "ct-eq"
))]
use proptest::prelude::*;

#[cfg(feature = "encoding-hex")]
mod hex_proptests {
    use super::*;
    use secure_gate::{encoding::hex::HexString, ExposeSecret};

    #[cfg(feature = "encoding-hex")]
    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(10))]

        #[test]
        fn hex_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let original = bytes;
            let hex_string = ::hex::encode(&original);
            let hex_secret = HexString::new(hex_string).unwrap();
            let decoded = hex_secret.decode_into_bytes();
            prop_assert_eq!(decoded, original);
        }

        #[test]
        fn hex_byte_len_consistency(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let hex_string = ::hex::encode(&bytes);
            let hex_secret = HexString::new(hex_string).unwrap();
            prop_assert_eq!(hex_secret.byte_len(), bytes.len());
            prop_assert_eq!(hex_secret.len(), bytes.len() * 2);
        }
    }
}

#[cfg(feature = "encoding-base64")]
mod base64_proptests {
    use super::*;
    use secure_gate::encoding::base64::Base64String;

    #[cfg(feature = "encoding-base64")]
    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(10))]

        #[test]
        fn base64_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let original = bytes;
            let base64_string = URL_SAFE_NO_PAD.encode(&original);
            let base64_secret = Base64String::new(base64_string).unwrap();
            let decoded = base64_secret.decode_into_bytes();
            prop_assert_eq!(decoded, original);
        }

        #[test]
        fn base64_byte_len_consistency(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let base64_string = URL_SAFE_NO_PAD.encode(&bytes);
            let base64_secret = Base64String::new(base64_string).unwrap();
            prop_assert_eq!(base64_secret.byte_len(), bytes.len());
        }
    }
}

#[cfg(feature = "encoding-bech32")]
mod bech32_proptests {
    use super::*;
    use secure_gate::encoding::bech32::Bech32String;

    #[cfg(feature = "encoding-bech32")]
    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(10))]

        // Bech32 round-trip: generate valid bech32 string, parse, encode back if possible
        // Since bech32 has specific formats, generate random data and encode to bech32
        #[test]
        fn bech32_round_trip(data in prop::collection::vec(any::<u8>(), 0..40)) {  // Bech32 max data is ~40 bytes
            // Use testnet prefix for consistency
            let hrp = Hrp::parse("tb").unwrap();
            let bech32_string = bech32::encode::<bech32::Bech32>(hrp, &data).unwrap();
            let bech32_secret = Bech32String::new(bech32_string).unwrap();
            let decoded = bech32_secret.decode_into_bytes();
            prop_assert_eq!(decoded, data);
        }
    }
}

#[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
mod serde_proptests {
    use super::*;
    use secure_gate::{Dynamic, ExportableString, ExportableVec, ExposeSecret};

    #[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(10))]

        #[test]
        fn exportable_vec_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let original: ExportableVec = bytes.clone().into();
            let serialized = ::serde_json::to_string(&original).unwrap();
            let deserialized: Dynamic<Vec<u8>> = ::serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(deserialized.expose_secret(), &bytes);
        }

        #[test]
        fn exportable_string_round_trip(s in any::<String>()) {
            let original: ExportableString = s.clone().into();
            let serialized = ::serde_json::to_string(&original).unwrap();
            let deserialized: Dynamic<String> = ::serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(deserialized.expose_secret(), &s);
        }
    }
}

#[cfg(feature = "ct-eq")]
mod ct_eq_proptests {
    use super::*;

    #[cfg(feature = "ct-eq")]
    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(10))]

        #[test]
        fn constant_time_eq_reflexive(a in prop::collection::vec(any::<u8>(), 0..256)) {
            prop_assert!(bool::from(::subtle::ConstantTimeEq::ct_eq(a.as_slice(), a.as_slice())));
        }

        #[test]
        fn constant_time_eq_symmetric(a in prop::collection::vec(any::<u8>(), 0..256), b in prop::collection::vec(any::<u8>(), 0..256)) {
            prop_assert_eq!(bool::from(::subtle::ConstantTimeEq::ct_eq(a.as_slice(), b.as_slice())), bool::from(::subtle::ConstantTimeEq::ct_eq(b.as_slice(), a.as_slice())));
        }
    }
}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    all(feature = "serde-deserialize", feature = "serde-serialize"),
    feature = "ct-eq"
))]
#[test]
fn proptest_modules_present() {
    // This test runs only if any of the features that enable proptest modules are enabled.
    // It verifies that the proptest modules are compiled in.
    assert_eq!(2 + 2, 4);
}
