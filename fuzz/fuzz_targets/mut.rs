#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{ExposeSecretMut, Secure, SecurePasswordMut};
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // ------------------------------------------------------------------
    // 1. SecurePasswordMut — full String abuse + explicit zeroization
    // ------------------------------------------------------------------
    let mut pw = SecurePasswordMut::from("hunter2");
    {
        let s = pw.expose_mut().expose_secret_mut();

        // Feed raw bytes — lossy conversion ensures we always get a valid String
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

        // Bounded random appends (cap at 1000 to avoid OOM)
        let append_count = (data[0] as usize % 150).min(1000);
        s.extend(std::iter::repeat('🚀').take(append_count));
    }

    // 50/50 chance to explicitly zeroize inner — tests manual wipe path
    if data[0] % 2 == 0 {
        pw.expose_mut().expose_secret_mut().zeroize();
    }

    // 50/50 chance to shrink excess capacity
    if data[0] % 4 == 0 {
        let _ = pw.finish_mut();
    }
    drop(pw);

    // ------------------------------------------------------------------
    // 2. Secure<Vec<u8>> — raw buffer torture
    // ------------------------------------------------------------------
    let mut bytes = Secure::<Vec<u8>>::new(vec![0xDE; 64]);
    {
        let v = bytes.expose_mut();
        v.clear();
        v.extend_from_slice(data);
        // Cap maximum allocation to prevent OOM
        let new_size = v.len() + data.len().min(500_000);
        v.resize(new_size, 0xFF);
        v.truncate(data.len() % 3000);
        v.retain(|_| data[0] % 5 != 0);
    }
    if data[0] % 3 == 0 {
        bytes.expose_mut().zeroize();
    }
    drop(bytes);

    // ------------------------------------------------------------------
    // 3. Fixed-size keys (stack or heap) + clone isolation
    // ------------------------------------------------------------------
    let mut key = Secure::<[u8; 32]>::new([0xAA; 32]);
    if !data.is_empty() {
        let idx = (data[0] as usize) % 32;
        key.expose_mut()[idx] = data[0];
    }
    let mut clone = key.clone();
    if data.len() > 1 {
        clone.expose_mut()[0] = data[1];
    }
    // Zeroize inner array (via Zeroize impl when available, e.g., with "stack")
    if data[0] % 7 == 0 {
        clone.expose_mut().zeroize();
    }
    drop(key);
    drop(clone);

    // ------------------------------------------------------------------
    // 4. Nested secure types — test deep zeroization
    // ------------------------------------------------------------------
    let mut nested = Secure::new(Secure::new(data.to_vec()));
    if data[0] % 11 == 0 {
        // Chain to inner for zeroization
        nested.expose_mut().expose_mut().zeroize();
    }
    drop(nested);

    // ------------------------------------------------------------------
    // 5. Additional edge cases for better coverage
    // ------------------------------------------------------------------
    // Test with very small inputs
    if data.len() >= 2 {
        let mut small = Secure::<[u8; 2]>::new([data[0], data[1]]);
        small.expose_mut()[0] = data[0].wrapping_add(1);
        drop(small);
    }
    // Test empty secure containers
    let mut empty_vec = Secure::<Vec<u8>>::new(Vec::new());
    if !data.is_empty() {
        empty_vec.expose_mut().push(data[0]);
    }
    // Zeroize empty (tests len=0 path)
    if data[0] % 13 == 0 {
        empty_vec.expose_mut().zeroize();
    }
    drop(empty_vec);
});
