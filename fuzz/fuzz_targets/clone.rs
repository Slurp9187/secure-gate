#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_gate::Secure;
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    // Test 1: Empty container lifecycle and clone behavior
    {
        let mut empty = Secure::<Vec<u8>>::new(Vec::new());
        let cloned_empty = empty.clone();

        assert_eq!(empty.expose().len(), 0);
        assert_eq!(cloned_empty.expose().len(), 0);

        drop(cloned_empty);
        empty.zeroize();
        assert_eq!(empty.expose().len(), 0);
    }

    if data.is_empty() {
        return; // Skip further tests for empty data
    }

    // Test 2: Basic isolation - clone mutation doesn't affect original
    let original_data = data.to_vec();
    let mut original = Secure::new(original_data.clone());
    let mut clone = original.clone();

    clone.expose_mut().push(0xFF);

    assert_eq!(original.expose(), &original_data);
    assert_eq!(clone.expose().len(), original_data.len() + 1);
    assert_eq!(clone.expose()[..original_data.len()], original_data[..]);
    assert_eq!(clone.expose()[original_data.len()], 0xFF);

    // Test 3: Original mutation doesn't affect clone
    original.expose_mut().push(0xAA);

    // Clone remains unchanged
    assert_eq!(clone.expose().len(), original_data.len() + 1);
    assert_eq!(original.expose().len(), original_data.len() + 1);

    // Test 4: Zeroization verification on original (byte-level)
    let pre_zero_content = original.expose().to_vec();
    original.zeroize();

    let exposed = original.expose();

    // All bytes must be zero
    assert!(
        exposed.iter().all(|&b| b == 0),
        "Zeroization failed: found non-zero bytes in {:?}",
        exposed
    );
    // Length must be unchanged
    assert_eq!(
        exposed.len(),
        pre_zero_content.len(),
        "Length changed after zeroization"
    );

    // Test 5: Clone remains intact after original zeroization
    assert_eq!(clone.expose().len(), original_data.len() + 1);
    assert_eq!(clone.expose()[..original_data.len()], original_data[..]);
    assert_eq!(clone.expose()[original_data.len()], 0xFF);

    // Test 6: Memory reallocation stress test on a clone of the clone
    let mut stress_clone = clone.clone();
    let old_capacity = stress_clone.expose().capacity();

    if let Some(new_cap) = old_capacity.checked_mul(2).and_then(|v| v.checked_add(1)) {
        stress_clone.expose_mut().reserve(new_cap);

        // Content should remain identical after reallocation
        assert_eq!(stress_clone.expose(), clone.expose());
    }

    // Test 7: Final extraction and validation via into_inner
    let extracted = stress_clone.into_inner();
    assert_eq!(*extracted, *clone.expose());

    // Test 8: String handling with arbitrary / malformed UTF-8
    let pw_str = String::from_utf8_lossy(data);
    let secure_str = Secure::new(pw_str.to_string());
    let str_clone = secure_str.clone();

    // Clone must be identical
    assert_eq!(secure_str.expose(), str_clone.expose());

    // Underlying string content must be preserved
    assert_eq!(secure_str.expose(), pw_str.as_ref());

    // Final cleanup: zeroize the remaining clone
    {
        clone.zeroize();
        let zeroed_clone = clone.expose();
        assert!(
            zeroed_clone.iter().all(|&b| b == 0),
            "Clone zeroization failed"
        );
    }
});
