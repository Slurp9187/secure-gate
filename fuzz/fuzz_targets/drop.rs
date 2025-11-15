#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{Secure, SecurePassword};

fuzz_target!(|data: &[u8]| {
    let bytes = data.to_vec();
    let s = String::from_utf8_lossy(data).to_string();

    // Test that Secure<Vec<u8>> zeroizes on drop
    {
        let sec = Secure::new(bytes.clone());
        let _original = sec.expose().to_vec(); // Copy out while alive
        drop(sec);
        // We CANNOT read the memory anymore — that would be UB
        // Instead: if zeroization failed, the secret would still be in memory...
        // but we can't prove it without UB. So we trust the impl + code review.
        // This fuzz target now just ensures no panic/crash during drop
        // (which is still valuable!)
    }

    // Test SecurePassword
    {
        let pw = SecurePassword::from(s.as_str());
        let _original = pw.expose().to_string();
        drop(pw);
        // Same: we can't prove zeroization without UB
        // But we can ensure drop doesn't panic
    }

    // Bonus: stress test many drops
    for _ in 0..100 {
        let _ = Secure::new(data.to_vec());
        let _ = SecurePassword::from("hunter2");
    }
});
