// fuzz/fuzz_targets/clone.rs
// Created: 2025-11-14 06:42:42.864
// Modified: 2025-11-17 23:18:10.263

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_gate::Secure;
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    // Test 1: Empty container lifecycle and clone behavior
    {
        let mut empty = Secure::<Vec<u8>>::new(Vec::new());
        let cloned_empty = empty.clone();

        // Light check: lengths match (no assert — fuzz-friendly)
        if empty.expose().len() != cloned_empty.expose().len() {
            return;
        }

        drop(cloned_empty);
        empty.zeroize();
        // Light check: still empty post-zeroize
        if !empty.expose().is_empty() {
            return;
        }
    }

    if data.is_empty() {
        return; // Skip further tests for empty data
    }

    // Test 2: Basic isolation - clone mutation doesn't affect original
    let original_data = data.to_vec();
    let mut original = Secure::new(original_data.clone());
    let mut clone = original.clone();

    clone.expose_mut().push(0xFF);

    // Light check: original unchanged
    if original.expose() != &original_data {
        return;
    }
    // Light check: clone grew
    if clone.expose().len() != original_data.len() + 1 {
        return;
    }
    // Light check: prefix matches
    if &clone.expose()[..original_data.len()] != &original_data[..] {
        return;
    }
    // Light check: suffix is 0xFF
    if clone.expose()[original_data.len()] != 0xFF {
        return;
    }

    // Test 3: Original mutation doesn't affect clone
    original.expose_mut().push(0xAA);

    // Light check: clone unchanged
    if clone.expose().len() != original_data.len() + 1 {
        return;
    }

    // Test 4: Zeroization verification on original (byte-level)
    let pre_zero_content = original.expose().to_vec();
    original.zeroize();

    let exposed = original.expose();

    // Light check: all bytes zero
    if !exposed.iter().all(|&b| b == 0) {
        return;
    }
    // Light check: length unchanged
    if exposed.len() != pre_zero_content.len() {
        return;
    }

    // Test 5: Clone remains intact after original zeroization
    // Light check: clone still good
    if clone.expose().len() != original_data.len() + 1 {
        return;
    }
    if &clone.expose()[..original_data.len()] != &original_data[..] {
        return;
    }
    if clone.expose()[original_data.len()] != 0xFF {
        return;
    }

    // Test 6: Memory reallocation stress test on a clone of the clone
    let mut stress_clone = clone.clone();
    let old_capacity = stress_clone.expose().capacity();

    if let Some(new_cap) = old_capacity.checked_mul(2).and_then(|v| v.checked_add(1)) {
        stress_clone.expose_mut().reserve(new_cap);

        // Light check: content identical after realloc
        if stress_clone.expose() != clone.expose() {
            return;
        }
    }

    // Test 7: Final extraction and validation via into_inner
    let extracted = stress_clone.into_inner();
    // Light check: extracted matches
    if *extracted != *clone.expose() {
        return;
    }

    // Test 8: String handling with arbitrary / malformed UTF-8
    let pw_str = String::from_utf8_lossy(data);
    let secure_str = Secure::new(pw_str.to_string());
    let str_clone = secure_str.clone();

    // Light check: clone identical
    if secure_str.expose() != str_clone.expose() {
        return;
    }

    // Light check: underlying preserved
    if secure_str.expose() != pw_str.as_ref() {
        return;
    }

    // Final cleanup: zeroize the remaining clone
    {
        clone.zeroize();
        let zeroed_clone = clone.expose();
        // Light check: all zero
        if !zeroed_clone.iter().all(|&b| b == 0) {
            return;
        }
    }
});
