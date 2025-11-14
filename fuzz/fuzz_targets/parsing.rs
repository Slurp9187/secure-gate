#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{Secure, SecureStr};

fuzz_target!(|s: &str| {
    // Focus on SecureStr (the only alias with FromStr impl)
    let _ = s.parse::<SecureStr>();
    let _ = SecureStr::from(s); // Direct from

    // Fuzz mutations on parsed values
    let sec_str = s.parse::<SecureStr>().unwrap(); // FIXED: Use .unwrap() (infallible)
    let _ = sec_str.expose().len(); // Stress deref
    let cloned = sec_str.clone(); // FIXED: No mut (unused anyway)
                                  // Use cloned in a no-op to satisfy unused warning (or drop it)
    drop(cloned);

    // Fuzz on Sized equivalent Secure<String>
    let mut sized = Secure::new(s.to_string());
    sized.finish_mut();

    // Edge cases: long strings, empty, unicode
    if s.len() > 1000 {
        let _ = s.parse::<SecureStr>(); // Alloc stress
    }
    let _ = "".parse::<SecureStr>(); // Empty
    let _ = "😀".parse::<SecureStr>(); // Unicode

    // If you add FromStr to other aliases (e.g., SecureKey32 via hex parse), fuzz them here
});
