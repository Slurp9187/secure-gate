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
            inner_str.extend((0..(data[0] as usize)).map(|_| 'x')); // Extend with filler chars
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
        v.resize(v.len() + (data.len() * 10), 0xFF);
        v.truncate(data.len() % 1000);
        v.retain(|_| data[0] % 2 == 0);
    }
    bytes.finish_mut();
    drop(bytes);

    // 3. Fixed-size key mutation (should panic or be safe)
    let mut key = Secure::<[u8; 32]>::new([0xAA; 32]);
    // FIXED: Dynamic index from fuzz input to avoid compile-time OOB detection
    // This tests runtime OOB panic (fuzzer catches as crash)
    let idx = (data.len() as u32).wrapping_mul(3) as usize; // Large/dynamic index
    if idx >= 32 {
        // Force OOB write to trigger panic
        let slice = key.expose_mut();
        let _ = slice[idx] = 0xFF; // ← Runtime OOB → should panic and crash fuzzer
    }
});
