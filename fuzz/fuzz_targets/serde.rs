// fuzz/fuzz_targets/serde.rs
//
// Fuzz target for all serde (de)serialization paths — untrusted input!

#![no_main]
use libfuzzer_sys::fuzz_target;

use secure_gate::{ExposeSecret, Secure, SecurePassword};

const MAX_INPUT: usize = 1_048_576; // 1 MiB — OOM-safe
const MAX_STRING: usize = 524_288; // 512 KiB — string guard

fuzz_target!(|data: &[u8]| {
    // 1. Hard OOM protection
    if data.len() > MAX_INPUT {
        return;
    }

    // 2. JSON → SecurePassword
    let _ = serde_json::from_slice::<SecurePassword>(data); // Force error paths too
    if let Ok(pw) = serde_json::from_slice::<SecurePassword>(data) {
        let _ = pw.expose_secret().len();
        drop(pw);
    }

    // 3. Bincode → Vec<u8> → Secure<Vec<u8>>
    let config = bincode::config::standard().with_limit::<MAX_INPUT>();
    let _ = bincode::decode_from_slice::<Vec<u8>, _>(data, config); // Probe errors
    if let Ok((vec, _)) = bincode::decode_from_slice::<Vec<u8>, _>(data, config) {
        if vec.len() > MAX_INPUT {
            return;
        }
        let sec = Secure::new(vec);
        let _ = sec.expose().len();
        drop(sec);
    }

    // 4. Bincode → String → SecurePassword
    let _ = bincode::decode_from_slice::<String, _>(data, config); // Probe errors
    if let Ok((s, _)) = bincode::decode_from_slice::<String, _>(data, config) {
        if s.len() > MAX_STRING {
            return;
        }
        let pw = SecurePassword::from(s.as_str());
        let _ = pw.expose_secret().len();
        drop(pw);
    }

    // 5. Large input stress: Simulate >1MB without OOM (repeat small chunks)
    if data.len() >= 1024 {
        // Only if non-trivial input
        for i in 0..=5 {
            // Bounded repeats
            let large = vec![data; i + 1]; // Up to 6x (6MB sim, but capped below)
            if large.concat().len() > MAX_INPUT * 2 {
                break;
            } // Edge without crash
            let _ = serde_json::from_slice::<SecurePassword>(&large.concat());
        }
    }
});
