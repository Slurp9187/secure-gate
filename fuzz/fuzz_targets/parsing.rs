// fuzz/fuzz_targets/parsing.rs
//
// Fuzz target for all FromStr / parsing paths (infallible but allocation-heavy)

#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{ExposeSecret, Secure, SecureBytes, SecurePassword, SecureStr};

const MAX_LEN: usize = 1_000_000; // Extreme alloc stress (1MB cap to avoid OOM)

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_LEN {
        return; // OOM guard
    }

    // 1. Non-UTF-8 path: SecureBytes from arbitrary bytes (no filtering!)
    let _bytes = SecureBytes::from(data.to_vec());
    let _ = _bytes.expose().len(); // Force deref on raw bytes

    // 2. UTF-8 path: Attempt parse (graceful fail on invalid)
    if let Ok(s) = std::str::from_utf8(data) {
        // Core SecureStr parsing (infallible per source)
        let _ = s.parse::<SecureStr>();
        let _ = SecureStr::from(s);

        // Post-parse stress: read-only + clone
        let sec_str = s.parse::<SecureStr>().unwrap(); // Safe unwrap
        let _ = sec_str.expose().len();

        // Clone + to_string stress
        let cloned = sec_str.clone();
        let _ = cloned.expose().to_string();
        drop(cloned);

        // SecurePassword from valid &str
        let pw: SecurePassword = s.into();
        let _ = pw.expose_secret();

        // Edge cases: empty/simple/unicode
        let _ = "".parse::<SecureStr>();
        let _ = "hello world".parse::<SecureStr>();
        let _ = "😀🚀".parse::<SecureStr>();

        // Alloc stress: long valid inputs
        if s.len() > 1000 {
            let _ = s.parse::<SecureStr>();
        }
        if s.len() > 5000 {
            let _ = s.parse::<SecureStr>();
        }
    }

    // 3. Mutation stress: Secure<String> on owned (lossy) data
    let owned = String::from_utf8_lossy(data).to_string();
    let mut sized_str = Secure::new(owned);
    sized_str.expose_mut().push('!'); // Possible realloc
    sized_str.expose_mut().push_str("_fuzz");
    sized_str.expose_mut().clear(); // Truncate to zero
    let _ = sized_str.finish_mut(); // Shrink-to-fit + zero excess

    // 4. Extreme alloc: Repeat parse on growing inputs (simulates exhaustion)
    for i in 0..=10 {
        // 10x stress, bounded
        if data.len().saturating_mul(i as usize) > MAX_LEN {
            break;
        }
        let repeated = vec![data; i.min(100)]; // Cap repeats to avoid OOM
        let repeated_bytes = SecureBytes::from(repeated.concat());
        let _ = repeated_bytes.expose().len();
    }

    // Final drop: Triggers zeroize on all
    drop(sized_str);
});
