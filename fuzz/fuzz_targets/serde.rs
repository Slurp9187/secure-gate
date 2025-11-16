#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{ExposeSecret, Secure, SecurePassword};

const MAX_SIZE: usize = 1_000_000; // Limit input size to 1MB to prevent OOM

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_SIZE {
        return; // Skip large inputs to avoid realloc/OOM
    }
    // JSON deserialization from untrusted data
    if let Ok(pw) = serde_json::from_slice::<SecurePassword>(data) {
        let _ = pw.expose().expose_secret().len();
        drop(pw);
    }
    let config = bincode::config::standard().with_limit(1024 * 1024); // 1 MB max (adjust as needed)
                                                                      // Bincode deserialization from untrusted data (inner Vec<u8>)
    if let Ok((vec, _)) = bincode::decode_from_slice::<Vec<u8>, _>(data, config) {
        if vec.len() > MAX_SIZE {
            return; // Skip oversized decoded data
        }
        let sec = Secure::new(vec);
        let _ = sec.expose().len();
        drop(sec);
    }
    // Bincode deserialization from untrusted data (inner String for SecurePassword)
    if let Ok((str_inner, _)) = bincode::decode_from_slice::<String, _>(data, config) {
        if str_inner.len() > MAX_SIZE {
            return;
        }
        let pw = SecurePassword::from(str_inner.as_str());
        let _ = pw.expose().expose_secret().len();
        drop(pw);
    }
    // Controlled round-trip (never leaks real secrets)
    let pw = SecurePassword::from("fuzzme");
    if let Ok(json) = serde_json::to_string(pw.expose().expose_secret()) {
        let _ = serde_json::from_str::<SecurePassword>(&json);
    }
    // Bincode round-trip for SecurePassword (via expose inner String)
    if let Ok(encoded) = bincode::encode_to_vec(pw.expose().expose_secret().to_string(), config) {
        let _ = bincode::decode_from_slice::<String, _>(&encoded, config);
    }
    let bytes = Secure::new(b"fuzzme".to_vec());
    if let Ok(encoded) = bincode::encode_to_vec(bytes.expose().to_vec(), config) {
        let _ = bincode::decode_from_slice::<Vec<u8>, _>(&encoded, config);
    }
});
