// fuzz/fuzz_targets/serde.rs
//
// Fuzz target for all serde (de)serialization paths — untrusted input!

#![no_main]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "serde")]
use secure_gate::SecureGate;

#[cfg(all(feature = "serde", feature = "zeroize"))]
use secure_gate::{ExposeSecret, SecurePassword};

const MAX_INPUT: usize = 1_048_576; // 1 MiB — OOM-safe

fuzz_target!(|data: &[u8]| {
    // Hard OOM protection
    if data.len() > MAX_INPUT {
        return;
    }

    // -------------------------------------------------
    // All serde-dependent code is inside these cfg blocks
    // -------------------------------------------------
    #[cfg(all(feature = "serde", feature = "zeroize"))]
    {
        // JSON → SecurePassword
        let _ = serde_json::from_slice::<SecurePassword>(data);
        if let Ok(pw) = serde_json::from_slice::<SecurePassword>(data) {
            let _ = pw.expose().expose_secret().len();
            drop(pw);
        }

        // Bincode → String → SecurePassword
        let config = bincode::config::standard().with_limit::<MAX_INPUT>();
        let _ = bincode::decode_from_slice::<String, _>(data, config);
        if let Ok((s, _)) = bincode::decode_from_slice::<String, _>(data, config) {
            let pw: SecurePassword = s.as_str().into();
            let _ = pw.expose().expose_secret().len();
            drop(pw);
        }
    }

    #[cfg(feature = "serde")]
    {
        // Bincode → Vec<u8> → SecureGate<Vec<u8>>
        let config = bincode::config::standard().with_limit::<MAX_INPUT>();
        let _ = bincode::decode_from_slice::<Vec<u8>, _>(data, config);
        if let Ok((vec, _)) = bincode::decode_from_slice::<Vec<u8>, _>(data, config) {
            if vec.len() > MAX_INPUT {
                return;
            }
            let sec = SecureGate::new(vec);
            let _ = sec.expose().len();
            drop(sec);
        }
    }

    // Large-input stress — still useful even without serde
    if data.len() >= 1024 {
        for i in 1..=5 {
            let repeated_len = data.len() * i as usize;
            if repeated_len > MAX_INPUT * 2 {
                break;
            }
            let _large = data.repeat(i as usize);

            // JSON stress only when serde + zeroize are enabled
            #[cfg(all(feature = "serde", feature = "zeroize"))]
            let _ = serde_json::from_slice::<SecurePassword>(&_large);
        }
    }
});
