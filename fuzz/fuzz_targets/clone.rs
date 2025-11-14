#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_types::{Secure, SecurePassword};

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 {
        return;
    }

    // Fuzz cloning + extraction on byte vectors
    let sec = Secure::<Vec<u8>>::new(data.to_vec());
    let _cloned = sec.clone(); // Triggers scoped zeroization via init_with
    let _extracted = _cloned.into_inner(); // Clone + wipe original

    // Fuzz SecurePassword cloning/extraction
    let pw = SecurePassword::init_with(|| {
        secure_types::SecretString(String::from_utf8_lossy(data).to_string())
    });
    let _extracted_pw = pw.into_inner(); // Should clone + zeroize original
});
