#![no_main]
use core::ops::DerefMut;
use libfuzzer_sys::fuzz_target;
use secure_gate::{Secure, SecurePassword}; // Enables deref_mut() for SecretString

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. SecurePassword: unbounded push/pop/clear/resize
    let mut pw = SecurePassword::from("initial");
    {
        let inner = pw.expose_mut(); // &mut SecretString
                                     // Fuzz arbitrary string mutations
        if let Ok(s) = core::str::from_utf8(data) {
            let inner_str = inner.deref_mut(); // &mut String
            inner_str.clear();
            inner_str.push_str(s);
            inner_str.truncate(data.len() % 1000);
            inner_str.extend((0..(data[0] as usize % 100)).map(|_| 'x')); // FIXED: Bound extend to 100 chars max
        }
    }
    pw.finish_mut(); // Some users call it, some don't — test both
    drop(pw);

    // 2. Secure<Vec<u8>>: unbounded resize, extend, push, pop, etc.
    let mut bytes = Secure::<Vec<u8>>::new(vec![0x42; 32]);
    {
        let v = bytes.expose_mut();
        v.clear();
        v.extend_from_slice(data);
        let extra_size = data.len().saturating_mul(10).min(1_000_000); // FIXED: Saturate at 1MB to avoid OOM
        v.resize(v.len() + extra_size, 0xFF);
        v.truncate(data.len() % 1000);
        v.retain(|_| data[0] % 2 == 0);
    }
    bytes.finish_mut();
    drop(bytes);

    // 3. Fixed-size key mutation (safe, bounded)
    let mut key = Secure::<[u8; 32]>::new([0xAA; 32]);
    // FIXED: Bound idx to array size (stress safe mutations)
    if !data.is_empty() {
        let idx = (data[0] as usize) % 32; // Safe index 0-31
        key.expose_mut()[idx] = data[0]; // Mutate within bounds
    }
    drop(key); // Stress drop after mutation
});
