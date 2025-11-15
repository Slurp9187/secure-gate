#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{Secure, SecurePassword};

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 {
        return;
    }
    // Fuzz cloning + extraction on byte vectors
    let sec = Secure::<Vec<u8>>::new(data.to_vec());
    // Triggers scoped zeroization via init_with
    let _cloned = sec.clone();
    // Clone + wipe original
    let _extracted = _cloned.into_inner();
    // Fuzz SecurePassword cloning/extraction (immutable default)
    let pw_str = String::from_utf8_lossy(data);
    let pw = SecurePassword::from(pw_str.as_ref());
    let _cloned_pw = pw.clone();
    // Clone + wipe original
    let _extracted_pw = _cloned_pw.into_inner();
});
