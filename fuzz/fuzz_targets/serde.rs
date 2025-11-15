// fuzz_targets/serde.rs — final clean version
#![no_main]
use core::ops::Deref; // FIXED: Import Deref for deref() on SecretString
use libfuzzer_sys::fuzz_target;
use secure_gate::{Secure, SecurePassword};

fuzz_target!(|data: &[u8]| {
    // JSON deserialization from untrusted data
    if let Ok(pw) = serde_json::from_slice::<SecurePassword>(data) {
        let _ = pw.expose().len();
        drop(pw);
    }

    let config = bincode::config::standard();

    // Bincode deserialization from untrusted data (inner Vec<u8>)
    if let Ok((vec, _)) = bincode::decode_from_slice::<Vec<u8>, _>(data, config) {
        let sec = Secure::new(vec);
        let _ = sec.expose().len();
        drop(sec);
    }

    // Bincode deserialization from untrusted data (inner String for SecurePassword)
    if let Ok((str_inner, _)) = bincode::decode_from_slice::<String, _>(data, config) {
        let pw = SecurePassword::from(str_inner.as_str());
        let _ = pw.expose().len();
        drop(pw);
    }

    // Controlled round-trip (never leaks real secrets)
    let pw = SecurePassword::from("fuzzme");
    if let Ok(json) = serde_json::to_string(&pw) {
        let _ = serde_json::from_str::<SecurePassword>(&json);
    }

    // Bincode round-trip for SecurePassword (via expose inner String)
    if let Ok(encoded) = bincode::encode_to_vec(pw.expose().deref(), config) {
        // FIXED: deref() now resolves
        let _ = bincode::decode_from_slice::<String, _>(&encoded, config);
    }

    let bytes = Secure::new(b"fuzzme".to_vec());
    if let Ok(encoded) = bincode::encode_to_vec(bytes.expose(), config) {
        let _ = bincode::decode_from_slice::<Vec<u8>, _>(&encoded, config);
    }
});
