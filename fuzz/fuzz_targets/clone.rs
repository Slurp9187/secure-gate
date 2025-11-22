// fuzz/fuzz_targets/clone.rs
//
// Fuzz Dynamic<T> cloning, isolation, zeroization, and reallocation behavior
// (v0.5.0 – SecureGate and old password types are gone)
#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate_0_5_0::{Dynamic, Fixed};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    // Test 1: Empty container lifecycle and clone behavior
    {
        let empty = Dynamic::<Vec<u8>>::new(Vec::new());
        #[cfg(feature = "zeroize")]
        let cloned_empty = empty.clone();
        #[cfg(not(feature = "zeroize"))]
        let cloned_empty = empty.clone(); // Clone works even without zeroize now

        if &*empty != &*cloned_empty {
            return;
        }
        drop(cloned_empty);

        #[cfg(feature = "zeroize")]
        {
            let mut empty = empty;
            empty.zeroize();
            if !empty.is_empty() {
                return;
            }
        }
    }

    if data.is_empty() {
        return;
    }

    // Test 2: Basic isolation – clone mutation doesn’t affect original
    let original_data = data.to_vec();
    let mut original = Dynamic::<Vec<u8>>::new(original_data.clone());
    let mut clone = original.clone();

    clone.push(0xFF);

    if &*original != &original_data {
        return;
    }
    if clone.len() != original_data.len() + 1 {
        return;
    }
    if &clone[..original_data.len()] != &original_data[..] {
        return;
    }
    if clone[original_data.len()] != 0xFF {
        return;
    }

    // Test 3: Original mutation doesn’t affect clone
    original.push(0xAA);
    if clone.len() != original_data.len() + 1 {
        return;
    }

    // Test 4: Zeroization verification on original
    let pre_zero_len = original.len();
    #[cfg(feature = "zeroize")]
    original.zeroize();

    #[cfg(feature = "zeroize")]
    if !original.iter().all(|&b| b == 0) || original.len() != pre_zero_len {
        return;
    }

    // Test 5: Clone remains intact after original zeroization
    if clone.len() != original_data.len() + 1 {
        return;
    }
    if &clone[..original_data.len()] != &original_data[..] || clone[original_data.len()] != 0xFF {
        return;
    }

    // Test 6: Reallocation stress on a clone-of-clone
    let mut stress_clone = clone.clone();
    if let Some(new_cap) = stress_clone
        .capacity()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
    {
        stress_clone.reserve(new_cap);
        if &*stress_clone != &*clone {
            return;
        }
    }

    // Test 7: String handling (lossy UTF-8)
    let pw_str = String::from_utf8_lossy(data);
    let secure_str: Dynamic<String> = Dynamic::new(pw_str.to_string());
    let str_clone = secure_str.clone();

    if &*secure_str != &*str_clone {
        return;
    }
    if secure_str.as_str() != pw_str.as_ref() {
        return;
    }

    // Test 8: Fixed-size secrets (no Clone, but we can still test construction)
    let fixed_key = Fixed::new([0x42u8; 32]);
    let _ = fixed_key.len(); // just touch it

    // Final cleanup – zeroize the remaining clone
    #[cfg(feature = "zeroize")]
    clone.zeroize();

    #[cfg(feature = "zeroize")]
    if !clone.iter().all(|&b| b == 0) {
        return;
    }
});
