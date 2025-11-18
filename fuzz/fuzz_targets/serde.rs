// fuzz/fuzz_targets/serde.rs
//
// Fuzz target for all serde (de)serialization paths — untrusted input!

#![no_main]
use libfuzzer_sys::fuzz_target;

use secure_gate::ExposeSecret;
use secure_gate::{Secure, SecurePassword};

const MAX_SIZE: usize = 1_000_000; // Prevent OOM

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_SIZE {
        return; // Skip huge inputs
    }

    // 1. JSON deserialization from untrusted data
    if let Ok(pw) = serde_json::from_slice::<SecurePassword>(data) {
        let _ = pw.expose_secret().len();
        drop(pw);
    }

    // 2. Bincode deserialization from untrusted data (inner Vec<u8>)
    if let Ok((vec, _)) =
        bincode::decode_from_slice::<Vec<u8>, _>(data, bincode::config::standard())
    {
        if vec.len() > MAX_SIZE {
            return;
        }
        let sec = Secure::new(vec);
        let _ = sec.expose().len();
        drop(sec);
    }

    // 3. Bincode deserialization from untrusted data (inner String → SecurePassword)
    if let Ok((str_inner, _)) =
        bincode::decode_from_slice::<String, _>(data, bincode::config::standard())
    {
        if str_inner.len() > MAX_SIZE {
            return;
        }
        let pw = SecurePassword::from(str_inner.as_str());
        let _ = pw.expose_secret().len();
        drop(pw);
    }

    // 4. Controlled round-trip (never leaks real secrets)
    let pw = SecurePassword::from("fuzzme");
    if let Ok(json) = serde_json::to_string(pw.expose_secret()) {
        let _ = serde_json::from_str::<SecurePassword>(&json);
    }

    // 5. Bincode round-trip for SecurePassword (via expose inner String)
    let config = bincode::config::standard();
    if let Ok(encoded) = bincode::encode_to_vec(pw.expose_secret().to_string(), config) {
        let _ = bincode::decode_from_slice::<String, _>(&encoded, config);
    }

    // 6. Secure<Vec<u8>> round-trip
    let bytes = Secure::new(b"fuzzme".to_vec());
    if let Ok(encoded) = bincode::encode_to_vec(bytes.expose().to_vec(), config) {
        let _ = bincode::decode_from_slice::<Vec<u8>, _>(&encoded, config);
    }
});
