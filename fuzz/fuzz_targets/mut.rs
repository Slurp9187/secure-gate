// fuzz/fuzz_targets/mut.rs
//
// Stress mutation, zeroization, builder paths, and nested secure types
// (v0.5.0 – SecureGate, SecurePasswordBuilder, etc. are gone; use Dynamic<T>)
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, Fixed};
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec, FuzzFixed32};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = arbitrary::Unstructured::new(data);

    let fixed_32 = match FuzzFixed32::arbitrary(&mut u) {
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

    // 1. Dynamic<String> — full String abuse + explicit zeroization
    #[cfg(feature = "zeroize")]
    {
        let mut pw = dyn_str.clone();
        let text = pw.expose_secret().clone();

        {
            let s = &mut *pw;
            s.clear();
            s.push_str(&text);
            let max_bytes = text.len() % 1800;
            let truncate_to = text
                .char_indices()
                .map(|(i, _)| i)
                .find(|&i| i > max_bytes)
                .unwrap_or(text.len());
            s.truncate(truncate_to);

            let append_count = (text.len() % 150).min(1000);
            for _ in 0..append_count {
                s.push('🚀');
            }
            pw.finish_mut();
        }

        if text.len() % 2 == 0 {
            pw.zeroize();
        }
    }

    // 2. Dynamic<Vec<u8>> — raw buffer torture
    let mut bytes = dyn_vec.clone();
    {
        let v = &mut *bytes;
        v.clear();
        v.extend_from_slice(data);
        let new_size = v.len().saturating_add(data.len().min(500_000));
        v.resize(new_size, 0xFF);
        v.truncate(data.len() % 3000);
        v.retain(|&b| b != data[0]);
    }
    #[cfg(feature = "zeroize")]
    if data[0] % 3 == 0 {
        bytes.zeroize();
    }
    drop(bytes);

    // 3. Fixed-size array + clone isolation
    let mut key = fixed_32;
    let original_first_byte = key[0]; // ← capture before mutation
    if data.len() > 1 {
        key[0] = !key[0];
        if original_first_byte == key[0] {
            panic!("Isolation failed");
        }
    }
    drop(key);

    // 4. Nested secure types
    let nested = Dynamic::<Dynamic<Vec<u8>>>::new(Dynamic::new(data.to_vec()));
    #[cfg(feature = "zeroize")]
    if data[0] % 11 == 0 {
        let mut inner = nested.clone();
        inner.zeroize();
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
