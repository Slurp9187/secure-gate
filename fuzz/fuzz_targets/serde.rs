// fuzz/fuzz_targets/serde.rs
//
// Serde serialize/deserialize round-trip fuzz target for secure-gate v0.8.0.
//
// Tests the serde paths flagged in AUDIT.md (F-02: intermediate Vec in Fixed
// deserialization; F-03: encoding constructors). Exercises:
//   - Deserialize for Fixed<[u8; 32]>, Dynamic<String>, Dynamic<Vec<u8>>
//   - Serialize for a locally-defined SerializableSecretVec wrapper
//   - Malformed JSON → graceful error (no panic)
//   - Corrupted-JSON round-trip → deserialize error (no panic)
//
// Corpus seed hints (paste into fuzz/corpus/serde/):
//   [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]
//   "hello world"
//   [72,101,108,108,111]
//   {}
//   null
//   true
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, Fixed, ExposeSecret, SerializableSecret};
use secure_gate_fuzz::arbitrary::FuzzJsonPayload;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// Local newtype that satisfies SerializableSecret so we can test the Serialize path.
// Using #[serde(transparent)] so it serializes as a plain Vec<u8> / byte array.
#[derive(Debug, Serialize, Deserialize, Zeroize, Clone)]
#[serde(transparent)]
struct SecretBytes(Vec<u8>);

impl SerializableSecret for SecretBytes {}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = Unstructured::new(data);

    // === 1. Deserialize Fixed<[u8; 32]> from arbitrary JSON (never panic) ===
    {
        let json: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let _ = serde_json::from_str::<Fixed<[u8; 32]>>(&json);

        // Also try structured payloads
        let payload = match FuzzJsonPayload::arbitrary(&mut u) {
            Ok(p) => p.0,
            Err(_) => return,
        };
        let _ = serde_json::from_str::<Fixed<[u8; 32]>>(&payload);
    }

    // === 2. Deserialize Dynamic<String> from arbitrary JSON ===
    {
        let json: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let _ = serde_json::from_str::<Dynamic<String>>(&json);

        // Valid JSON string round-trip
        let s: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let json_string = serde_json::to_string(&s).unwrap_or_default();
        if let Ok(recovered) = serde_json::from_str::<Dynamic<String>>(&json_string) {
            assert_eq!(
                recovered.expose_secret(),
                &s,
                "Dynamic<String> serde round-trip failed"
            );
        }
    }

    // === 3. Deserialize Dynamic<Vec<u8>> from arbitrary JSON ===
    {
        let json: String = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let _ = serde_json::from_str::<Dynamic<Vec<u8>>>(&json);

        // Valid JSON array round-trip: [0,1,2,...] → Dynamic<Vec<u8>>
        let bytes: Vec<u8> = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let capped = if bytes.len() > 512 {
            &bytes[..512]
        } else {
            &bytes[..]
        };
        let json_array = serde_json::to_string(capped).unwrap_or_default();
        if let Ok(recovered) = serde_json::from_str::<Dynamic<Vec<u8>>>(&json_array) {
            assert_eq!(
                recovered.expose_secret(),
                capped,
                "Dynamic<Vec<u8>> serde round-trip failed"
            );
        }
    }

    // === 4. Fixed<[u8; 32]> known-good round-trip ===
    {
        // JSON representation of Fixed<[u8; 32]> is a 32-element array
        let arr: [u8; 32] = Arbitrary::arbitrary(&mut u).unwrap_or([0u8; 32]);
        let json = serde_json::to_string(&arr.to_vec()).unwrap_or_default();
        if let Ok(fixed) = serde_json::from_str::<Fixed<[u8; 32]>>(&json) {
            assert_eq!(
                fixed.expose_secret(),
                &arr,
                "Fixed<[u8; 32]> serde round-trip failed"
            );
        }
    }

    // === 5. Serialize via SecretBytes, deserialize as Dynamic<Vec<u8>> ===
    // Deserialize is only implemented for Dynamic<String> and Dynamic<Vec<u8>>.
    // SecretBytes is #[serde(transparent)] over Vec<u8>, so JSON produced by
    // serializing Dynamic<SecretBytes> is identical to serializing Dynamic<Vec<u8>>.
    {
        let inner_bytes: Vec<u8> = Arbitrary::arbitrary(&mut u).unwrap_or_default();
        let capped = if inner_bytes.len() > 512 {
            inner_bytes[..512].to_vec()
        } else {
            inner_bytes
        };

        let secret = Dynamic::<SecretBytes>::new(SecretBytes(capped.clone()));
        if let Ok(json) = serde_json::to_string(&secret) {
            // Deserialize the same JSON as Dynamic<Vec<u8>> (same wire format)
            if let Ok(recovered) = serde_json::from_str::<Dynamic<Vec<u8>>>(&json) {
                assert_eq!(
                    *recovered.expose_secret(),
                    capped,
                    "Serialize<SecretBytes>/Deserialize<Vec<u8>> round-trip failed"
                );
            }
        }
    }

    // === 6. Corrupted JSON → graceful error ===
    {
        // Start with valid JSON array, corrupt one byte, verify graceful error
        let arr: [u8; 32] = Arbitrary::arbitrary(&mut u).unwrap_or([0u8; 32]);
        if let Ok(mut json_bytes) = serde_json::to_string(&arr.to_vec()).map(|s| s.into_bytes()) {
            if !json_bytes.is_empty() {
                // Flip the last byte
                let last = json_bytes.len() - 1;
                json_bytes[last] ^= 0xFF;
                if let Ok(corrupted) = String::from_utf8(json_bytes) {
                    let _ = serde_json::from_str::<Fixed<[u8; 32]>>(&corrupted);
                }
            }
        }
    }

    // === 7. Malformed / edge-case JSON strings ===
    {
        for bad in &[
            "",
            "null",
            "true",
            "{}",
            "[]",
            "\"string\"",
            "[1,2,3]",               // too short for Fixed<[u8;32]>
            &"[0]".repeat(33),       // too many elements
        ] {
            let _ = serde_json::from_str::<Fixed<[u8; 32]>>(bad);
            let _ = serde_json::from_str::<Dynamic<String>>(bad);
            let _ = serde_json::from_str::<Dynamic<Vec<u8>>>(bad);
        }
    }
});
