// fuzz/fuzz_targets/debug.rs — full fixed file (replace the entire contents)

#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{Secure, SecurePassword};
use std::format;

fuzz_target!(|data: &[u8]| {
    // Skip empty
    if data.is_empty() {
        return;
    }

    // 1. Secure<Vec<u8>>
    let sec = Secure::<Vec<u8>>::new(data.to_vec());
    let debug = format!("{:?}", sec);
    assert!(debug.contains("[REDACTED]"));

    // 2. SecurePassword — only test valid UTF-8
    if let Ok(pw_str) = std::str::from_utf8(data) {
        if pw_str.is_empty() {
            return;
        }

        let pw = SecurePassword::from(pw_str);
        let debug_pw = format!("{:?}", pw);
        assert!(debug_pw.contains("[REDACTED]"));

        // Skip if pw_str is a substring of the fixed redacted output
        if !"Secure<[REDACTED]>".contains(pw_str) {
            assert!(!debug_pw.contains(pw_str));
        }
    }

    // 3. Mutation + drop
    let mut sec_mut = Secure::<Vec<u8>>::new(data.to_vec());
    sec_mut.finish_mut();
    let _ = format!("{:?}", sec_mut);
    drop(sec_mut);

    // 4. Fallback mode
    let fallback = Secure::<Vec<u8>>::new(data.to_vec());
    let debug_f = format!("{:?}", fallback);
    assert!(debug_f.contains("[REDACTED]"));
});
