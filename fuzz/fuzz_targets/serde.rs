// fuzz_targets/serde.rs — final clean version
#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_types::{Secure, SecurePassword};

fuzz_target!(|data: &[u8]| {
    // JSON deserialization from untrusted data
    if let Ok(pw) = serde_json::from_slice::<SecurePassword>(data) {
        let _ = pw.expose().len();
        drop(pw);
    }

    let config = bincode::config::standard();

    // Bincode deserialization from untrusted data
    if let Ok((vec, _)) = bincode::decode_from_slice::<Vec<u8>, _>(data, config) {
        let sec = Secure::new(vec);
        let _ = sec.expose().len();
        drop(sec);
    }

    // Controlled round-trip (never leaks real secrets)
    let pw = SecurePassword::from("fuzzme");
    if let Ok(json) = serde_json::to_string(&pw) {
        let _ = serde_json::from_str::<SecurePassword>(&json);
    }

    let bytes = Secure::new(b"fuzzme".to_vec());
    if let Ok(encoded) = bincode::encode_to_vec(bytes.expose(), config) {
        let _ = bincode::decode_from_slice::<Vec<u8>, _>(&encoded, config);
    }
});
