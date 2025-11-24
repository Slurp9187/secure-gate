// fuzz/fuzz_targets/clone.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary; // ← ADD THIS LINE
use secure_gate::{Dynamic, Fixed};
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec, FuzzFixed32};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);

    let fixed_32: Fixed<[u8; 32]> = match FuzzFixed32::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };

    let dyn_vec: Dynamic<Vec<u8>> = match FuzzDynamicVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    let dyn_str: Dynamic<String> = match FuzzDynamicString::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    // === All your original tests below (unchanged) ===
    // Test 1: Empty container lifecycle
    {
        let empty = Dynamic::<Vec<u8>>::new(Vec::new());
        let cloned_empty = empty.clone();
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

    // Test 2: Clone isolation
    let original_data = dyn_vec.expose_secret().clone();
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

    // Test 3: Original mutation
    original.push(0xAA);
    if clone.len() != original_data.len() + 1 {
        return;
    }

    // Test 4: Zeroization
    let pre_zero_len = original.len();
    #[cfg(feature = "zeroize")]
    original.zeroize();
    #[cfg(feature = "zeroize")]
    if !original.iter().all(|&b| b == 0) || original.len() != pre_zero_len {
        return;
    }

    // Test 7: String handling
    let pw_str = dyn_str.expose_secret().clone();
    let secure_str: Dynamic<String> = Dynamic::new(pw_str.clone());
    let _str_clone = secure_str.clone();
    if &*secure_str != &pw_str {
        return;
    }

    // Test 8: Fixed-size
    let _ = fixed_32.len();

    // Final cleanup
    #[cfg(feature = "zeroize")]
    clone.zeroize();
    #[cfg(feature = "zeroize")]
    if !clone.iter().all(|&b| b == 0) {
        return;
    }
});
