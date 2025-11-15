// fuzz/fuzz_targets/expose.rs (full fixed file)
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
    let pw_str = String::from_utf8_lossy(data);
    let mut pw = SecurePassword::from(pw_str.as_ref()); // Immutable default
    pw.finish_mut(); // Shrink string cap (no-op for str, but safe)
    let _ = pw.expose(); // View (returns &str)
});
