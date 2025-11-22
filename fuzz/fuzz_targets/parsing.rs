// fuzz/fuzz_targets/parsing.rs
//
// Fuzz target for all parsing paths — SecureStr, SecureBytes, SecurePassword, and extreme allocation stress

#![no_main]
use libfuzzer_sys::fuzz_target;

use secure_gate::{SecureBytes, SecureGate, SecureStr};

#[cfg(feature = "zeroize")]
use secure_gate::{ExposeSecret, SecurePassword};

const MAX_LEN: usize = 1_000_000; // 1MB cap to avoid OOM

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_LEN {
        return;
    }

    // 1. SecureBytes — raw arbitrary bytes (no UTF-8 required)
    let _bytes: SecureBytes = data.to_vec().into();
    let _ = _bytes.expose().len();

    // 2. UTF-8 path — only if valid
    if let Ok(s) = std::str::from_utf8(data) {
        // SecureStr parsing — infallible
        let _ = s.parse::<SecureStr>();
        let _ = SecureStr::from(s);

        // Stress: clone + to_string
        let sec_str = SecureStr::from(s);
        let _ = sec_str.expose().len();
        let cloned = sec_str.clone();
        let _ = cloned.expose().to_string();
        drop(cloned);

        // SecurePassword from &str (zeroize feature only)
        #[cfg(feature = "zeroize")]
        {
            let pw: SecurePassword = s.into();
            let _ = pw.expose().expose_secret();
        }

        // Edge cases with emoji glory
        let _ = "".parse::<SecureStr>().unwrap();
        let _ = "hello world".parse::<SecureStr>().unwrap();
        let _ = "grinning face rocket".parse::<SecureStr>().unwrap(); // emoji preserved!

        // Allocation stress on long valid strings
        if s.len() > 1_000 {
            let _ = s.parse::<SecureStr>();
        }
        if s.len() > 5_000 {
            let _ = s.parse::<SecureStr>();
        }
    }

    // 3. Mutation stress — lossy UTF-8 → owned String → SecureGate<String>
    let owned = String::from_utf8_lossy(data).into_owned();
    let mut sized_str = SecureGate::new(owned);
    sized_str.expose_mut().push('!');
    sized_str.expose_mut().push_str("_fuzz");
    sized_str.expose_mut().clear();
    let _ = sized_str.finish_mut(); // shrink_to_fit + return &mut String

    // 4. Extreme allocation stress — repeated data
    for i in 1..=10 {
        if data.len().saturating_mul(i as usize) > MAX_LEN {
            break;
        }
        let repeated = std::iter::repeat(data)
            .take(i.min(100))
            .flatten()
            .copied()
            .collect::<Vec<u8>>();
        let repeated_bytes: SecureBytes = repeated.into();
        let _ = repeated_bytes.expose().len();
    }

    // Final drop — triggers zeroization when feature enabled
    drop(sized_str);
});
