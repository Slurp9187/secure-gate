// fuzz/fuzz_targets/mut.rs
//
// Stress mutation, zeroization, builder paths, and nested secure types

#![no_main]
use libfuzzer_sys::fuzz_target;

use secure_gate::SecureGate;

#[cfg(feature = "zeroize")]
use secure_gate::{ExposeSecretMut, SecurePasswordBuilder};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. SecurePasswordBuilder — full String abuse + explicit zeroization
    #[cfg(feature = "zeroize")]
    {
        let mut pw = SecurePasswordBuilder::from("hunter2");
        {
            let s = pw.expose_mut().expose_secret_mut();
            let text = String::from_utf8_lossy(data);
            s.clear();
            s.push_str(&text);

            // Random valid truncate point
            let max_bytes = data.len() % 1800;
            let truncate_to = text
                .char_indices()
                .map(|(i, _)| i)
                .find(|&i| i > max_bytes)
                .unwrap_or(text.len());
            s.truncate(truncate_to);

            // Bounded random appends — EMOJI TIME!
            let append_count = (data[0] as usize % 150).min(1000);
            s.extend(std::iter::repeat("").take(append_count));
        }

        // 50/50 chance to manually zeroize inner String
        if data[0] % 2 == 0 {
            pw.expose_mut().expose_secret_mut().zeroize();
        }

        // Manual shrink_to_fit
        if data[0] % 4 == 0 {
            pw.expose_mut().expose_secret_mut().shrink_to_fit();
        }

        // into_password() zeroizes the builder
        let _ = pw.into_password();
    }

    // 2. Secure<Vec<u8>> — raw buffer torture
    let mut bytes = SecureGate::new(vec![0xDE; 64]);
    {
        let v = bytes.expose_mut();
        v.clear();
        v.extend_from_slice(data);
        let new_size = v.len() + data.len().min(500_000);
        v.resize(new_size, 0xFF);
        v.truncate(data.len() % 3000);
        v.retain(|_| data[0] % 5 != 0);
    }

    #[cfg(feature = "zeroize")]
    if data[0] % 3 == 0 {
        bytes.zeroize();
    }
    drop(bytes);

    // 3. Fixed-size heap keys + clone isolation
    let key_arr = {
        let mut arr = [0xAAu8; 32];
        if !data.is_empty() {
            let idx = (data[0] as usize) % 32;
            arr[idx] = data[0];
        }
        arr
    };
    let key = SecureGate::new(key_arr);
    let mut clone = key.clone();

    if data.len() > 1 {
        clone.expose_mut()[0] = data[1];
    }

    drop(key);
    drop(clone);

    // 4. Nested secure types
    let nested = SecureGate::new(SecureGate::new(data.to_vec()));
    #[cfg(feature = "zeroize")]
    if data[0] % 11 == 0 {
        let mut inner = nested.clone(); // ← clone to avoid move
        inner.expose_mut().zeroize();
    }
    drop(nested);

    // 5. Edge cases
    if data.len() >= 2 {
        let mut small = SecureGate::new([data[0], data[1]]);
        small.expose_mut()[0] = data[0].wrapping_add(1);
        drop(small);
    }

    let mut empty_vec = SecureGate::<Vec<u8>>::new(Vec::new());
    if !data.is_empty() {
        empty_vec.expose_mut().push(data[0]);
    }
    #[cfg(feature = "zeroize")]
    if data[0] % 13 == 0 {
        empty_vec.zeroize();
    }
    drop(empty_vec);
});
