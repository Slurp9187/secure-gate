#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{Secure, SecurePassword};

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 {
        return;
    } // Skip empty

    // Fuzz Secure<u8> (byte arrays, e.g., keys)
    let mut sec = Secure::<Vec<u8>>::new(data.to_vec());
    let _ = sec.expose(); // Stress deref
    sec.expose_mut().clear(); // Mutate + potential realloc
    sec.finish_mut(); // Shrink + zero excess

    // Fuzz SecurePassword (strings)
    let pw_str = std::str::from_utf8(data).unwrap_or_default();
    let mut pw = SecurePassword::from(pw_str);
    *pw.expose_mut() = secure_gate::SecretString(pw_str.to_string()); // FIXED: Wrap in SecretString for From impl
    pw.finish_mut(); // Shrink string cap
    let _ = pw.expose().as_str(); // View coercion
});
