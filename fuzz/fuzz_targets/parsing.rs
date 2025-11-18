// fuzz/fuzz_targets/parsing.rs
//
// Fuzz target for all FromStr / parsing paths (infallible but allocation-heavy)

#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{ExposeSecret, Secure, SecurePassword, SecureStr};

// Safe UTF-8 conversion for byte fuzz inputs
fn safe_str(data: &[u8]) -> Option<&str> {
    std::str::from_utf8(data).ok()
}

fuzz_target!(|data: &[u8]| {
    // Skip non-UTF-8 to focus on str parsing
    let s = if let Some(safe) = safe_str(data) {
        safe
    } else {
        return;
    };

    // Core SecureStr parsing (infallible per source)
    let _ = s.parse::<SecureStr>();
    let _ = SecureStr::from(s);

    // Post-parse stress: read-only + clone (SecureStr is immutable)
    let sec_str = s.parse::<SecureStr>().unwrap(); // Infallible; unwrap safe
    let _ = sec_str.expose().len(); // Deref/read

    // Clone + stress (tests to_string() + re-wrap zeroing)
    let cloned = sec_str.clone();
    let _ = cloned.expose().to_string(); // Light op: forces clone exposure
    drop(cloned);

    // Mutation stress: Shift to sized Secure<String> (growable)
    let mut sized_str = Secure::new(s.to_string());
    // Varied mutations on exposed String
    sized_str.expose_mut().push('!');
    sized_str.expose_mut().push_str("_fuzz");
    sized_str.expose_mut().clear(); // Full truncate
                                    // Shrink + zero excess (source: handles String)
    let _ = sized_str.finish_mut(); // Returns &mut String post-shrink

    // SecurePassword from &str (immutable path)
    let pw: SecurePassword = s.into();
    let _ = pw.expose_secret();

    // Edge cases (infallible parses)
    let _ = "".parse::<SecureStr>(); // Empty
    let _ = "hello world".parse::<SecureStr>(); // Simple
    let _ = "😀🚀".parse::<SecureStr>(); // Multi-byte Unicode

    // Alloc stress: long inputs trigger Box<str> heap
    if s.len() > 1000 {
        let _ = s.parse::<SecureStr>();
    }
    if s.len() > 5000 {
        let _ = s.parse::<SecureStr>();
    }

    // Final sanity: re-parse (regression guard)
    let final_check = s.parse::<SecureStr>();
    drop(final_check);
});
