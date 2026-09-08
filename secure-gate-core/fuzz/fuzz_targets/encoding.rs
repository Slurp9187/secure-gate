// Encoding/decoding round-trip fuzz target for `secure-gate`.
// Exercises hex, base64url, base32, bech32, and bech32m with structured payloads
// and arbitrary bytes.
//
// Invariants:
//   - decode(encode(raw)) == raw          (lossless round-trip)
//   - encode(decode(encode(raw))) == encode(raw)  (stable re-encoding)
//   - decode(arbitrary) never panics       (graceful error handling)
//
// "Stable re-encoding" is asserted only on encoder-produced strings. Base32
// decoding accepts non-canonical trailing bits ("MZ" decodes to the same byte as
// "MY"), so re-encoding an arbitrary *valid* string need not reproduce it.
//
// Corpus seed hints (paste into fuzz/corpus/encoding/):
//   "deadbeef"                     (valid hex, 4 bytes)
//   "QkJCQg"                       (base64url of [0x42; 4])
//   "NBSWY3DP"                     (base32 of b"hello")
//   "test1vehk7cnpwgry9h76"        (bech32 with payload)
//   "fuzz1dpjkcmr0ypmk7unvvsh4u4u" (bech32m with payload)
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{
    Dynamic, RevealSecret, Fixed,
    FromBech32Str,
    ToBech32, ToBech32m, ToBase32, ToBase64Url, ToHex,
};
use secure_gate_fuzz::arbitrary::{
    FuzzBase32String, FuzzBase64String, FuzzBech32String, FuzzDynamicVec, FuzzFixed16, FuzzFixed32,
    FuzzHexString,
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
            let re_encoded = decoded.expose_secret().to_hex().into_inner();
            assert_eq!(hex_str, re_encoded, "Hex round-trip not stable");
        }
    }

    // 1c. Fixed<[u8; 32]> hex round-trip
    {
        if let Ok(fixed) = FuzzFixed32::arbitrary(&mut u) {
            let hex = fixed.0.expose_secret().to_hex().into_inner();
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
            let re_encoded = decoded.expose_secret().to_base64url().into_inner();
            assert_eq!(b64_str, re_encoded, "Base64url round-trip not stable");
        }
    }

    // 2c. Fixed<[u8; 16]> base64url round-trip
    {
        if let Ok(fixed16) = FuzzFixed16::arbitrary(&mut u) {
            let b64 = fixed16.0.expose_secret().to_base64url().into_inner();
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

    // === BASE32 (RFC 4648 §6 — uppercase, unpadded) ===

    // 3a. Arbitrary strings to try_from_base32 — no panic
    {
        let arbitrary_str: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let _ = Fixed::<[u8; 32]>::try_from_base32(&arbitrary_str);
        let _ = Dynamic::<Vec<u8>>::try_from_base32(&arbitrary_str);
    }

    // 3b. Valid base32 round-trip. `FuzzBase32String` is produced by the
    // independent `base32` crate, so this compares two implementations and the
    // input is canonical — the precondition for the stable re-encoding check.
    {
        let b32_str = match FuzzBase32String::arbitrary(&mut u) {
            Ok(b) => b.0,
            Err(_) => return,
        };
        if let Ok(decoded) = Dynamic::<Vec<u8>>::try_from_base32(&b32_str) {
            let re_encoded = decoded.expose_secret().to_base32().into_inner();
            assert_eq!(b32_str, re_encoded, "Base32 round-trip not stable");
        }
    }

    // 3c. Fixed<[u8; 16]> base32 round-trip (16 bytes ↔ 26 chars)
    {
        if let Ok(fixed16) = FuzzFixed16::arbitrary(&mut u) {
            let b32 = fixed16.0.expose_secret().to_base32().into_inner();
            assert_eq!(b32.len(), 26, "16 bytes must encode to 26 base32 chars");
            let recovered = Fixed::<[u8; 16]>::try_from_base32(&b32)
                .expect("base32 from valid encode");
            assert_eq!(recovered.expose_secret(), fixed16.0.expose_secret(), "Fixed base32 RT");
        }
    }

    // 3d. Base32 edge cases
    {
        let _ = Dynamic::<Vec<u8>>::try_from_base32("");          // empty is valid
        let _ = Dynamic::<Vec<u8>>::try_from_base32("MY======");  // padding = invalid
        let _ = Dynamic::<Vec<u8>>::try_from_base32("nbswy3dp");  // lowercase = invalid
        let _ = Dynamic::<Vec<u8>>::try_from_base32("AAAAA");     // valid 3-byte
        let _ = Dynamic::<Vec<u8>>::try_from_base32("M");         // length ≡ 1 (mod 8) = invalid
        let _ = Dynamic::<Vec<u8>>::try_from_base32("MZ");        // non-canonical trailing bits
    }

    // === BECH32 (BIP-173, default code length) ===

    // 4a. Arbitrary strings to try_from_bech32_unchecked — no panic
    {
        let arbitrary_str: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let _ = Dynamic::<Vec<u8>>::try_from_bech32_unchecked(&arbitrary_str);
        let _ = Fixed::<[u8; 4]>::try_from_bech32_unchecked(&arbitrary_str);
    }

    // 4b. Valid bech32 round-trip via ToBech32 blanket impl on &[u8]
    {
        let dyn_vec = match FuzzDynamicVec::arbitrary(&mut u) {
            Ok(d) => d.0,
            Err(_) => return,
        };
        let raw = dyn_vec.expose_secret();
        // Cap to avoid enormous strings
        let capped = if raw.len() > 90 { &raw[..90] } else { &raw[..] };

        if let Ok(encoded) = capped.try_to_bech32("fuzz") {
            let decoded = Dynamic::<Vec<u8>>::try_from_bech32(&encoded, "fuzz")
                .expect("bech32 from valid encode");
            assert_eq!(decoded.expose_secret(), capped, "Bech32 round-trip failed");
        }
    }

    // 4b-sized. Same round-trip at a caller-chosen code length, with payloads that
    // exceed the default. The invariants: a large `N` encodes what the default
    // refuses; the decoder needs an `N` at least as large; and `N` never changes the
    // bytes, so a payload that fits both encodes identically at either.
    {
        const BIG: usize = 4096;

        let dyn_vec = match FuzzDynamicVec::arbitrary(&mut u) {
            Ok(d) => d.0,
            Err(_) => return,
        };
        let raw = dyn_vec.expose_secret();
        // 2 KiB of payload still fits BIG with room to spare for any HRP here.
        let capped = if raw.len() > 2048 { &raw[..2048] } else { &raw[..] };

        // Every capped payload fits BIG (2048 bytes -> 3288 chars < 4096), so an Err
        // here is a regression in the sized encode gate, not a legitimate refusal.
        let encoded = capped
            .try_to_bech32_sized::<BIG>("fuzz")
            .expect("sized bech32 encode refused a payload that fits").into_inner();
        {
            let decoded = Dynamic::<Vec<u8>>::try_from_bech32_sized::<BIG>(&encoded, "fuzz")
                .expect("sized bech32 from valid encode");
            assert_eq!(
                decoded.expose_secret(),
                capped,
                "sized Bech32 round-trip failed"
            );

            // The code length is a gate, not an input: whenever the default also
            // admits this payload, the two encodings must be identical.
            if let Ok(at_default) = capped.try_to_bech32("fuzz") {
                assert_eq!(
                    &*at_default, &*encoded,
                    "code length must not change the encoding"
                );
            } else {
                // Otherwise the default decoder must refuse the longer string
                // rather than truncating it.
                assert!(
                    Dynamic::<Vec<u8>>::try_from_bech32(&encoded, "fuzz").is_err(),
                    "default decoder accepted an over-long string"
                );
            }
        }

        // Bech32m at the same code length: same properties, and the two checksums
        // must never decode as one another.
        let encoded_m = capped
            .try_to_bech32m_sized::<BIG>("fuzz")
            .expect("sized bech32m encode refused a payload that fits").into_inner();
        {
            let decoded = Dynamic::<Vec<u8>>::try_from_bech32m_sized::<BIG>(&encoded_m, "fuzz")
                .expect("sized bech32m from valid encode");
            assert_eq!(
                decoded.expose_secret(),
                capped,
                "sized Bech32m round-trip failed"
            );
            assert!(
                Dynamic::<Vec<u8>>::try_from_bech32_sized::<BIG>(&encoded_m, "fuzz").is_err(),
                "bech32m string decoded as bech32"
            );
        }
    }

    // 4c. Pre-generated valid bech32 strings — should decode without panic
    {
        let bech32_str = match FuzzBech32String::arbitrary(&mut u) {
            Ok(b) => b.0,
            Err(_) => return,
        };
        let _ = Dynamic::<Vec<u8>>::try_from_bech32_unchecked(&bech32_str);
    }

    // 4d. HRP round-trip: encode with hrp, decode, verify hrp preserved
    {
        if let Ok(encoded) = b"hello".try_to_bech32("mykey") {
            let (hrp, payload) = (*encoded)
                .try_from_bech32_unchecked()
                .expect("valid bech32");
            assert_eq!(hrp.to_ascii_lowercase(), "mykey");
            assert_eq!(payload, b"hello");
        }
    }

    // 4e. Bech32 edge cases
    {
        let _ = Dynamic::<Vec<u8>>::try_from_bech32_unchecked("not-bech32");
        let _ = Dynamic::<Vec<u8>>::try_from_bech32_unchecked("1"); // no HRP
        let _ = Dynamic::<Vec<u8>>::try_from_bech32_unchecked("");
    }

    // === BECH32M (BIP-350, default code length) ===

    // 5a. Arbitrary strings to try_from_bech32m — no panic
    {
        let arbitrary_str: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let _ = Dynamic::<Vec<u8>>::try_from_bech32m_unchecked(&arbitrary_str);
    }

    // 5b. Valid bech32m round-trip (32 bytes: an address-sized payload)
    {
        let dyn_vec2 = match FuzzDynamicVec::arbitrary(&mut u) {
            Ok(d) => d.0,
            Err(_) => return,
        };
        let raw2 = dyn_vec2.expose_secret();
        let capped2 = if raw2.len() > 32 { &raw2[..32] } else { &raw2[..] };

        if let Ok(encoded) = capped2.try_to_bech32m("fuzz") {
            let decoded = Dynamic::<Vec<u8>>::try_from_bech32m(&encoded, "fuzz")
                .expect("bech32m from valid encode");
            assert_eq!(decoded.expose_secret(), capped2, "Bech32m round-trip failed");
        }
    }

    // 5c. Bech32m edge cases
    {
        let _ = Dynamic::<Vec<u8>>::try_from_bech32m_unchecked("not-bech32m");
        let _ = Dynamic::<Vec<u8>>::try_from_bech32m_unchecked("");
        let _ = Dynamic::<Vec<u8>>::try_from_bech32m_unchecked("1");
    }
});
