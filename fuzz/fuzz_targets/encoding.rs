// fuzz/fuzz_targets/encoding.rs
//
// Encoding/decoding round-trip fuzz target for secure-gate v0.8.0.
// Tests hex, base64url, bech32, and bech32m formats with both valid and arbitrary inputs.
//
// Invariants:
//   - decode(encode(raw)) == raw          (lossless round-trip)
//   - encode(decode(encode(raw))) == encode(raw)  (stable re-encoding)
//   - decode(arbitrary) never panics       (graceful error handling)
//
// Corpus seed hints (paste into fuzz/corpus/encoding/):
//   "deadbeef"                     (valid hex, 4 bytes)
//   "QkJCQg"                       (base64url of [0x42; 4])
//   "test1vehk7cnpwgry9h76"        (bech32 with payload)
//   "fuzz1dpjkcmr0ypmk7unvvsh4u4u" (bech32m with payload)
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{
    Dynamic, ExposeSecret, Fixed,
    FromBech32Str,
    ToBech32, ToBech32m, ToBase64Url, ToHex,
};
use secure_gate_fuzz::arbitrary::{
    FuzzBase64String, FuzzBech32String, FuzzDynamicVec, FuzzFixed16, FuzzFixed32, FuzzHexString,
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = Unstructured::new(data);

    // === HEX ===

    // 1a. Arbitrary strings to try_from_hex — must never panic
    {
        let arbitrary_str: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let _ = Fixed::<[u8; 32]>::try_from_hex(&arbitrary_str);
        let _ = Dynamic::<Vec<u8>>::try_from_hex(&arbitrary_str);
    }

    // 1b. Valid hex round-trip: encode bytes → hex string → decode → compare
    {
        let hex_str = match FuzzHexString::arbitrary(&mut u) {
            Ok(h) => h.0,
            Err(_) => return,
        };
        if let Ok(decoded) = Dynamic::<Vec<u8>>::try_from_hex(&hex_str) {
            let re_encoded = decoded.expose_secret().to_hex();
            assert_eq!(hex_str, re_encoded, "Hex round-trip not stable");
        }
    }

    // 1c. Fixed<[u8; 32]> hex round-trip
    {
        if let Ok(fixed) = FuzzFixed32::arbitrary(&mut u) {
            let hex = fixed.0.expose_secret().to_hex();
            let recovered = Fixed::<[u8; 32]>::try_from_hex(&hex).expect("hex from valid encode");
            assert_eq!(recovered.expose_secret(), fixed.0.expose_secret(), "Fixed hex round-trip");
        }
    }

    // 1d. Hex edge cases
    {
        let _ = Dynamic::<Vec<u8>>::try_from_hex("");
        let _ = Dynamic::<Vec<u8>>::try_from_hex("0");     // odd length
        let _ = Dynamic::<Vec<u8>>::try_from_hex("xyz!");  // invalid chars
        let _ = Dynamic::<Vec<u8>>::try_from_hex("AABBCC"); // uppercase
        let _ = Fixed::<[u8; 0]>::try_from_hex("");
    }

    // === BASE64URL ===

    // 2a. Arbitrary strings to try_from_base64url — no panic
    {
        let arbitrary_str: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let _ = Fixed::<[u8; 32]>::try_from_base64url(&arbitrary_str);
        let _ = Dynamic::<Vec<u8>>::try_from_base64url(&arbitrary_str);
    }

    // 2b. Valid base64url round-trip
    {
        let b64_str = match FuzzBase64String::arbitrary(&mut u) {
            Ok(b) => b.0,
            Err(_) => return,
        };
        if let Ok(decoded) = Dynamic::<Vec<u8>>::try_from_base64url(&b64_str) {
            let re_encoded = decoded.expose_secret().to_base64url();
            assert_eq!(b64_str, re_encoded, "Base64url round-trip not stable");
        }
    }

    // 2c. Fixed<[u8; 16]> base64url round-trip
    {
        if let Ok(fixed16) = FuzzFixed16::arbitrary(&mut u) {
            let b64 = fixed16.0.expose_secret().to_base64url();
            let recovered = Fixed::<[u8; 16]>::try_from_base64url(&b64)
                .expect("base64url from valid encode");
            assert_eq!(recovered.expose_secret(), fixed16.0.expose_secret(), "Fixed base64 RT");
        }
    }

    // 2d. Base64 edge cases
    {
        let _ = Dynamic::<Vec<u8>>::try_from_base64url("");
        let _ = Dynamic::<Vec<u8>>::try_from_base64url("====");  // padding = invalid
        let _ = Dynamic::<Vec<u8>>::try_from_base64url("AAAA"); // valid 3-byte
    }

    // === BECH32 (Bech32Large — extended capacity) ===

    // 3a. Arbitrary strings to try_from_bech32 — no panic
    {
        let arbitrary_str: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let _ = Dynamic::<Vec<u8>>::try_from_bech32(&arbitrary_str);
        let _ = Fixed::<[u8; 4]>::try_from_bech32(&arbitrary_str);
    }

    // 3b. Valid bech32 round-trip via ToBech32 blanket impl on &[u8]
    {
        let dyn_vec = match FuzzDynamicVec::arbitrary(&mut u) {
            Ok(d) => d.0,
            Err(_) => return,
        };
        let raw = dyn_vec.expose_secret();
        // Cap to avoid enormous strings
        let capped = if raw.len() > 90 { &raw[..90] } else { &raw[..] };

        if let Ok(encoded) = capped.try_to_bech32("fuzz", None) {
            let decoded =
                Dynamic::<Vec<u8>>::try_from_bech32(&encoded).expect("bech32 from valid encode");
            assert_eq!(decoded.expose_secret(), capped, "Bech32 round-trip failed");
        }
    }

    // 3c. Pre-generated valid bech32 strings — should decode without panic
    {
        let bech32_str = match FuzzBech32String::arbitrary(&mut u) {
            Ok(b) => b.0,
            Err(_) => return,
        };
        let _ = Dynamic::<Vec<u8>>::try_from_bech32(&bech32_str);
    }

    // 3d. HRP round-trip: encode with hrp, decode, verify hrp preserved
    {
        if let Ok(encoded) = b"hello".try_to_bech32("mykey", None) {
            let (hrp, payload) = encoded.as_str().try_from_bech32().expect("valid bech32");
            assert_eq!(hrp.to_ascii_lowercase(), "mykey");
            assert_eq!(payload, b"hello");
        }
    }

    // 3e. Bech32 edge cases
    {
        let _ = Dynamic::<Vec<u8>>::try_from_bech32("not-bech32");
        let _ = Dynamic::<Vec<u8>>::try_from_bech32("1");       // no HRP
        let _ = Dynamic::<Vec<u8>>::try_from_bech32("");
    }

    // === BECH32M (BIP-350, 90-byte payload limit) ===

    // 4a. Arbitrary strings to try_from_bech32m — no panic
    {
        let arbitrary_str: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let _ = Dynamic::<Vec<u8>>::try_from_bech32m(&arbitrary_str);
    }

    // 4b. Valid bech32m round-trip (cap to 32 bytes for BIP-350 compliance)
    {
        let dyn_vec2 = match FuzzDynamicVec::arbitrary(&mut u) {
            Ok(d) => d.0,
            Err(_) => return,
        };
        let raw2 = dyn_vec2.expose_secret();
        let capped2 = if raw2.len() > 32 { &raw2[..32] } else { &raw2[..] };

        if let Ok(encoded) = capped2.try_to_bech32m("fuzz", None) {
            let decoded = Dynamic::<Vec<u8>>::try_from_bech32m(&encoded)
                .expect("bech32m from valid encode");
            assert_eq!(decoded.expose_secret(), capped2, "Bech32m round-trip failed");
        }
    }

    // 4c. Bech32m edge cases
    {
        let _ = Dynamic::<Vec<u8>>::try_from_bech32m("not-bech32m");
        let _ = Dynamic::<Vec<u8>>::try_from_bech32m("");
        let _ = Dynamic::<Vec<u8>>::try_from_bech32m("1");
    }
});
