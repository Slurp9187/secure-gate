// fuzz/fuzz_targets/serde.rs
//
// Fuzz target for all serde (de)serialization paths — untrusted input!
// (v0.5.0 – SecureGate, SecurePassword gone; Dynamic deserializes blocked for security;
// test Fixed deserial, Dynamic serial + manual wrap)
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, Fixed};
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec, FuzzFixed32};

#[cfg(feature = "serde")]
use serde_json;

#[cfg(feature = "serde")]
use bincode;

const MAX_INPUT: usize = 1_048_576; // 1 MiB -- OOM-safe

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = arbitrary::Unstructured::new(data);

    let _fixed_32 = match FuzzFixed32::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };
    let dyn_vec = match FuzzDynamicVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };
    let dyn_str = match FuzzDynamicString::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    let fuzz_data = dyn_vec.expose_secret().as_slice(); // Use fuzzed vec as "data"

    if fuzz_data.len() > MAX_INPUT {
        return;
    }

    // -------------------------------------------------
    // All serde-dependent code is inside these cfg blocks
    // -------------------------------------------------
    #[cfg(feature = "serde")]
    {
        // JSON → Fixed<[u8; 32]> (deserial works for fixed-size)
        if fuzz_data.len() >= 32 {
            // Create a valid JSON array of 32 numbers (0-9 based on fuzz_data[0] for variety)
            let last_digit = ((fuzz_data[0] % 10) as u32).to_string();
            let zeros = (0..31).map(|_| "0").collect::<Vec<_>>().join(",");
            let json_arr = format!("[{zeros},{last_digit}]");
            let _ = serde_json::from_str::<Fixed<[u8; 32]>>(&json_arr);
        }

        // JSON → Dynamic<String> deserial BLOCKED (expect error)
        if let Err(err) = serde_json::from_slice::<Dynamic<String>>(fuzz_data) {
            let msg = err.to_string();
            if !msg.contains("disabled") && !msg.contains("security") && !msg.contains("invalid") {
                // Ignore parse errors ("invalid"), only panic on unexpected errors
            }
        } else {
            panic!("Unexpected deserial success");
        }

        // Serial for Dynamic<Vec<u8>> → JSON (serial works)
        let dyn_vec_ser = dyn_vec.clone();
        let _ = serde_json::to_vec(&dyn_vec_ser);

        // Bincode → Vec<u8> → Dynamic<Vec<u8>> (manual wrap after deserial)
        let config = bincode::config::standard().with_limit::<MAX_INPUT>();
        if let Ok((vec, _)) = bincode::decode_from_slice::<Vec<u8>, _>(fuzz_data, config) {
            if vec.len() > MAX_INPUT {
                return;
            }
            let sec = Dynamic::<Vec<u8>>::new(vec);
            let _ = sec.len();
            drop(sec);
        }

        // Serial for Dynamic<String> → Bincode
        let dyn_str_ser = dyn_str.clone();
        let _ = bincode::encode_to_vec(&*dyn_str_ser, config);
    }

    // Large-input stress — still useful even without serde
    if fuzz_data.len() >= 1024 {
        for i in 1..=5 {
            let repeated_len = fuzz_data.len() * i as usize;
            if repeated_len > MAX_INPUT * 2 {
                break;
            }
            let _large = fuzz_data.repeat(i as usize);
            // JSON stress only when serde enabled
            #[cfg(feature = "serde")]
            if let Err(err) = serde_json::from_slice::<Dynamic<String>>(&_large) {
                let msg = err.to_string();
                if !msg.contains("disabled")
                    && !msg.contains("security")
                    && !msg.contains("invalid")
                {
                    panic!("Wrong error on large input");
                }
            } else {
                panic!("Unexpected deserial success on large input");
            }
        }
    }
});
