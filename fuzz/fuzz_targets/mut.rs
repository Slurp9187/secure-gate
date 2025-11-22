// fuzz/fuzz_targets/mut.rs
//
// Stress mutation, zeroization, builder paths, and nested secure types
// (v0.5.0 – SecureGate, SecurePasswordBuilder, etc. are gone; use Dynamic<T>)
#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate_0_5_0::{Dynamic, Fixed};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. Dynamic<String> — full String abuse + explicit zeroization (replaces SecurePasswordBuilder)
    #[cfg(feature = "zeroize")]
    {
        let mut pw = Dynamic::<String>::new("hunter2".to_string());
        {
            let s = &mut *pw; // DerefMut
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
            for _ in 0..append_count {
                s.push('🚀'); // Emoji stress
            }
            pw.finish_mut(); // shrink_to_fit
        }
        // 50/50 chance to manually zeroize inner String
        if data[0] % 2 == 0 {
            pw.zeroize();
        }
    }

    // 2. Dynamic<Vec<u8>> — raw buffer torture
    let mut bytes = Dynamic::<Vec<u8>>::new(vec![0xDE; 64]);
    {
        let v = &mut *bytes; // DerefMut
        v.clear();
        v.extend_from_slice(data);
        let new_size = v.len().saturating_add(data.len().min(500_000));
        v.resize(new_size, 0xFF);
        v.truncate(data.len() % 3000);
        v.retain(|&b| b != data[0]); // Simplified retain
    }
    #[cfg(feature = "zeroize")]
    if data[0] % 3 == 0 {
        bytes.zeroize();
    }
    drop(bytes);

    // 3. Fixed-size array + clone isolation (Fixed doesn't clone, but we can test mutation isolation via copies)
    let key_arr = {
        let mut arr = [0xAAu8; 32];
        if !data.is_empty() {
            let idx = (data[0] as usize) % 32;
            arr[idx] = data[0];
        }
        arr
    };
    let mut key = Fixed::new(key_arr);
    let clone_arr = *key;
    if data.len() > 1 {
        // Mutate to a guaranteed different value using bitwise NOT ( !x != x for all u8)
        key[0] = !key[0];
        // Verify isolation: clone should remain unchanged
        if clone_arr[0] == key[0] {
            panic!("Isolation failed");
        }
    }
    drop(key);

    // 4. Nested secure types (Dynamic<Dynamic<Vec<u8>>>)
    let nested = Dynamic::<Dynamic<Vec<u8>>>::new(Dynamic::new(data.to_vec()));
    #[cfg(feature = "zeroize")]
    if data[0] % 11 == 0 {
        let mut inner = nested.clone(); // Clone the outer, then mutate inner
        inner.zeroize(); // Zeroize the inner Dynamic
    }
    drop(nested);

    // 5. Edge cases
    if data.len() >= 2 {
        let mut small = Fixed::new([data[0], data[1]]);
        small[0] = data[0].wrapping_add(1);
        drop(small);
    }

    let mut empty_vec = Dynamic::<Vec<u8>>::new(Vec::new());
    if !data.is_empty() {
        empty_vec.push(data[0]);
    }
    #[cfg(feature = "zeroize")]
    if data[0] % 13 == 0 {
        empty_vec.zeroize();
    }
    drop(empty_vec);
});
