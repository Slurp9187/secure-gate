#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{Secure, SecurePassword};

fuzz_target!(|data: &[u8]| {
    // Force the secret to live on the heap
    let secret_bytes = data.to_vec();
    let secret_str = String::from_utf8_lossy(data).to_string();

    // 1. Drop Secure<Vec<u8>> and try to "read back" via raw pointer (simulated leak)
    {
        let sec = Secure::new(secret_bytes.clone());
        let ptr = sec.expose().as_ptr();
        let len = sec.expose().len();
        drop(sec); // ← ZeroizeOnDrop should wipe it

        // Simulate attacker reading the memory after drop
        // SAFETY: ptr is still valid (heap), but contents should be zero
        unsafe {
            for i in 0..len.min(64) {
                let byte = core::ptr::read(ptr.add(i));
                // If any original byte survives, we found a zeroization bug
                if byte == secret_bytes[i % secret_bytes.len()] {
                    // This should NEVER happen — but if it does, crash!
                    panic!("Zeroization failed — byte survived drop!");
                }
            }
        }
    }

    // 2. Same for SecurePassword (SecretString wrapper)
    {
        let pw = SecurePassword::from(secret_str.as_str());
        let ptr = pw.expose().as_ptr();
        let len = pw.expose().len();
        drop(pw);

        unsafe {
            for i in 0..len.min(64) {
                let byte = core::ptr::read(ptr.add(i));
                if byte == secret_str.as_bytes()[i % secret_str.len()] {
                    panic!("SecretString zeroization failed!");
                }
            }
        }
    }
});
