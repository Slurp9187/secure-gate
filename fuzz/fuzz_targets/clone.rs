#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{Secure, SecurePassword};
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    } // Skip empty for non-trivial cases

    // Byte vector: clone + mutate original + extract clone
    let mut sec = Secure::<Vec<u8>>::new(data.to_vec());
    sec.expose_mut().reserve((data.len() % 1024) + 1); // Stress realloc on clone
    let _cloned = sec.clone(); // Zeros temp via init_with
    sec.expose_mut().push(b'\0'); // Mutate original post-clone
    sec.zeroize(); // Explicit wipe
    let _extracted = _cloned.into_inner(); // Wipe clone source

    // SecurePassword: string clone + extract
    let pw_str = String::from_utf8_lossy(data);
    let pw = SecurePassword::from(pw_str.as_ref());
    let _cloned_pw = pw.clone();
    // Removed mutation and finish_mut since type resolves to immutable str
    let _extracted_pw = _cloned_pw.into_inner(); // Wipe clone
});
