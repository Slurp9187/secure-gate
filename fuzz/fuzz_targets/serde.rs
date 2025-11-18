// fuzz/fuzz_targets/serde.rs
//
// Fuzz target for all serde (de)serialization paths — untrusted input!

#![no_main]
use libfuzzer_sys::fuzz_target;

use secure_gate::{ExposeSecret, Secure, SecurePassword};

const MAX_INPUT: usize = 1_048_576; // 1 MiB — generous but OOM-safe
const MAX_STRING: usize = 524_288; // 512 KiB — extra guard for String

fuzz_target!(|data: &[u8]| {
    // --------------------------------------------------------------
    // 1. Hard OOM protection — reject anything too big up front
    // --------------------------------------------------------------
    if data.len() > MAX_INPUT {
        return;
    }

    // --------------------------------------------------------------
    // 2. JSON → SecurePassword (most common real-world path)
    // --------------------------------------------------------------
    if let Ok(pw) = serde_json::from_slice::<SecurePassword>(data) {
        // Only read length — never expose the secret in fuzz target
        let _ = pw.expose_secret().len();
        drop(pw);
    }

    // --------------------------------------------------------------
    // 3. Bincode → Vec<u8> → Secure<Vec<u8>>
    // --------------------------------------------------------------
    let config = bincode::config::standard().with_limit::<MAX_INPUT>();
    if let Ok((vec, _)) = bincode::decode_from_slice::<Vec<u8>, _>(data, config) {
        // Extra sanity — bincode can still produce huge Vecs on malformed data
        if vec.len() > MAX_INPUT {
            return;
        }
        let sec = Secure::new(vec);
        let _ = sec.expose().len();
        drop(sec);
    }

    // --------------------------------------------------------------
    // 4. Bincode → String → SecurePassword
    // --------------------------------------------------------------
    if let Ok((s, _)) = bincode::decode_from_slice::<String, _>(data, config) {
        if s.len() > MAX_STRING {
            return;
        }
        let pw = SecurePassword::from(s.as_str());
        let _ = pw.expose_secret().len();
        drop(pw);
    }

    // --------------------------------------------------------------
    // 5. Controlled round-trip sanity checks (never leaks real secrets)
    // --------------------------------------------------------------
    let pw = SecurePassword::from("hunter2");

    // JSON round-trip
    if let Ok(json) = serde_json::to_string(pw.expose_secret()) {
        let _ = serde_json::from_str::<SecurePassword>(&json);
    }

    // Bincode round-trip via exposed String
    if let Ok(encoded) = bincode::encode_to_vec(pw.expose_secret().to_string(), config) {
        let _ = bincode::decode_from_slice::<String, _>(&encoded, config);
    }

    // Secure<Vec<u8>> round-trip
    let bytes = Secure::new(b"fuzzme".to_vec());
    if let Ok(encoded) = bincode::encode_to_vec(bytes.expose(), config) {
        let _ = bincode::decode_from_slice::<Vec<u8>, _>(&encoded, config);
    }
});
