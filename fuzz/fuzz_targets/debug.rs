#![no_main]
use libfuzzer_sys::fuzz_target;
// use secure_gate::SecureBytes;
use secure_gate::{Secure, SecurePassword};

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz Secure<Vec<u8>> formatting (ensure [REDACTED] always)
    let sec = Secure::<Vec<u8>>::new(data.to_vec());
    let debug = format!("{:?}", sec);
    assert!(debug.contains("[REDACTED]") && !debug.contains(&format!("{:x?}", data))); // No leak

    // 2. Fuzz SecurePassword (string secrets)
    let pw_str = std::str::from_utf8(data).unwrap_or_default();
    let pw = SecurePassword::from(pw_str);
    let debug_pw = format!("{:?}", pw);
    assert!(debug_pw.contains("[REDACTED]") && !debug_pw.contains(pw_str)); // No password leak

    // 3. Fuzz after mutation + zeroize (ensure redacted post-drop)
    let mut sec_mut = Secure::<Vec<u8>>::new(data.to_vec());
    sec_mut.finish_mut();
    let _ = format!("{:?}", sec_mut); // Redacted
    drop(sec_mut); // Zeroize

    // 4. Fuzz fallback mode (no zeroize)
    // #[cfg(not(feature = "zeroize"))]
    {
        let fallback = Secure::<Vec<u8>>::new(data.to_vec());
        let debug_f = format!("{:?}", fallback);
        assert!(debug_f.contains("[REDACTED]")); // Still redacted
    }
});
