// fuzz/fuzz_targets/mut.rs
//
// Mutation + zeroization stress target for secure-gate v0.6.0
// No Deref, explicit expose only, zero warnings, works with --no-default-features
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, Fixed};
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec, FuzzFixed32};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = Unstructured::new(data);

    // Generate valid gated instances
    let fixed_32 = match FuzzFixed32::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };

    let dyn_vec = match FuzzDynamicVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    // We actually use the string in zeroize path → keep it, just silence warning when zeroize is off
    let dyn_str = match FuzzDynamicString::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    // 1. Dynamic<String> — full mutation torture + explicit zeroize
    #[cfg(feature = "zeroize")]
    {
        let mut pw: Dynamic<String> = Dynamic::new(dyn_str.expose_secret().clone());
        let text = pw.expose_secret().clone();

        {
            let s = pw.expose_secret_mut();
            s.clear();
            s.push_str(&text);

            // Truncate to random byte length (not char boundary → stress UTF-8 handling)
            let max_bytes = text.len() % 1800;
            let truncate_to = text
                .char_indices()
                .map(|(i, _)| i)
                .find(|&i| i > max_bytes)
                .unwrap_or(text.len());
            s.truncate(truncate_to);

            // Append tons of wide chars
            let append_count = (text.len() % 150).min(1000);
            for _ in 0..append_count {
                s.push('🚀');
            }
        }
        pw.expose_secret_mut().shrink_to_fit();

        if text.len() % 2 == 0 {
            pw.zeroize();
        }
        drop(pw);
    }

    // When zeroize is disabled we still want to consume dyn_str to keep coverage identical
    #[cfg(not(feature = "zeroize"))]
    {
        let _ = &dyn_str; // prevents unused variable warning
    }

    // 2. Dynamic<Vec<u8>> — raw buffer abuse
    let mut bytes: Dynamic<Vec<u8>> = Dynamic::new(dyn_vec.expose_secret().clone());
    {
        let v = bytes.expose_secret_mut();
        v.clear();
        v.extend_from_slice(data);
        let new_size = v.len().saturating_add(data.len().min(500_000));
        v.resize(new_size, 0xFF);
        v.truncate(data.len().saturating_add(1) % 3000);
        v.retain(|&b| b != data[0]);
    }

    #[cfg(feature = "zeroize")]
    if data[0] % 3 == 0 {
        bytes.zeroize();
    }
    drop(bytes);

    // 3. Fixed<[u8; 32]> — clone isolation + mutation
    let mut key = fixed_32;
    let original_first = key.expose_secret()[0];
    if data.len() > 1 {
        key.expose_secret_mut()[0] = !original_first;
        if key.expose_secret()[0] == original_first {
            panic!("Fixed mutation isolation failed");
        }
    }

    // 4. Nested Dynamic<Dynamic<Vec<u8>>>
    let nested = Dynamic::<Dynamic<Vec<u8>>>::new(Dynamic::new(data.to_vec()));
    #[cfg(feature = "zeroize")]
    if data[0] % 11 == 0 {
        let mut inner: Dynamic<Dynamic<Vec<u8>>> =
            Dynamic::new(Dynamic::new(nested.expose_secret().expose_secret().clone()));
        inner.zeroize();
    }
    drop(nested);

    // 5. Small Fixed + empty Dynamic edge cases
    if data.len() >= 2 {
        let mut small = Fixed::new([data[0], data[1]]);
        small.expose_secret_mut()[0] = data[0].wrapping_add(1);
    }

    let mut empty_vec = Dynamic::<Vec<u8>>::new(Vec::new());
    if !data.is_empty() {
        empty_vec.expose_secret_mut().push(data[0]);
    }
    #[cfg(feature = "zeroize")]
    if data[0] % 13 == 0 {
        empty_vec.zeroize();
    }
    drop(empty_vec);
});
