#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::Secure;
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    // Test empty: direct path for zero-len edges
    if data.is_empty() {
        let mut sec_empty = Secure::<Vec<u8>>::new(Vec::new());
        let cloned_empty = sec_empty.clone();
        drop(cloned_empty); // Stress drop isolation
        sec_empty.zeroize();
        assert_eq!(sec_empty.expose().len(), 0); // Verify wipe
        return;
    }

    // Non-empty: Byte vector lifecycle (clone → mutate clone → verify original → wipe/extract)
    let mut sec = Secure::<Vec<u8>>::new(data.to_vec());
    sec.expose_mut().reserve(data.len().saturating_add(1)); // Simple realloc stress
    let mut cloned = sec.clone(); // Temp zeroed via init_with
    cloned.expose_mut().push(b'\xFF'); // Mutate *clone* (isolate from original)
    assert_eq!(sec.expose().len(), data.len()); // Original unchanged
    assert_eq!(cloned.expose().len(), data.len() + 1); // Clone mutated
    sec.zeroize(); // Explicit wipe original
    assert!(sec.expose().iter().all(|&b| b == 0)); // Verify all-zero (for Vec<u8>)
    let extracted = cloned.into_inner(); // Wipe clone source
    assert_eq!(extracted.len(), data.len() + 1); // Extracted intact
    drop(extracted); // Final drop

    // SecurePassword: String lifecycle (raw UTF-8, clone → mutate clone → verify → wipe)
    // FIXED: Use Secure<String> explicitly for mutability (avoids str fallback)
    let pw_inner = String::from_utf8(data.to_vec()).expect("Fuzz invalid UTF-8"); // Crash on bombs
    let mut pw = Secure::new(pw_inner.clone()); // Wrap as Secure<String> for push_str
    let mut cloned_pw = pw.clone();
    cloned_pw.expose_mut().push_str("!"); // Mutate clone (String supports this)
    assert_eq!(pw.expose().as_str(), &pw_inner); // Original isolated
    assert_eq!(cloned_pw.expose().as_str(), format!("{}{}", pw_inner, "!")); // Clone mutated
    pw.finish_mut(); // Shrink (noop if no excess, but stresses)
    pw.zeroize(); // Wipe original
    assert_eq!(pw.expose().len(), 0); // Verify empty post-wipe
    let extracted_pw = cloned_pw.into_inner(); // Wipe clone
    assert_eq!(&**extracted_pw, format!("{}{}", pw_inner, "!").as_str()); // Intact (Box<String>)
    drop(extracted_pw);
});
