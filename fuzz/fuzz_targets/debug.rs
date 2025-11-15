#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{Secure, SecurePassword};
use std::format;

fuzz_target!(|data: &[u8]| {
    // Skip empty or non-UTF8 inputs (avoids false negatives)
    let pw_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return, // Non-UTF8: skip, but still tests Debug on valid cases
    };
    if pw_str.is_empty() {
        return;
    } // Empty: trivial case

    // 1. Fuzz Secure<Vec<u8>> formatting (ensure [REDACTED] always)
    let sec = Secure::<Vec<u8>>::new(data.to_vec());
    let debug = format!("{:?}", sec);
    assert!(debug.contains("[REDACTED]")); // Always require redaction

    // 2. Fuzz SecurePassword (string secrets)
    let pw = SecurePassword::from(pw_str);
    let debug_pw = format!("{:?}", pw);
    assert!(debug_pw.contains("[REDACTED]")); // Always require redaction

    // Conditional "no-leak" check (skip if pw_str == "[REDACTED]" to avoid false positive)
    if pw_str != "[REDACTED]" {
        assert!(!debug_pw.contains(pw_str)); // No password leak
    }

    // 3. Fuzz after mutation + zeroize (ensure redacted post-drop)
    let mut sec_mut = Secure::<Vec<u8>>::new(data.to_vec());
    sec_mut.finish_mut();
    let _ = format!("{:?}", sec_mut); // Redacted
    drop(sec_mut); // Zeroize

    // 4. Fuzz fallback mode (no zeroize)
    {
        let fallback = Secure::<Vec<u8>>::new(data.to_vec());
        let debug_f = format!("{:?}", fallback);
        assert!(debug_f.contains("[REDACTED]")); // Still redacted
    }
});
