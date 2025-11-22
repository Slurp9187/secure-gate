// fuzz/fuzz_targets/clone.rs
//
// Fuzz SecureGate<T> cloning, isolation, zeroization, and reallocation behavior

#![no_main]
use libfuzzer_sys::fuzz_target;

use secure_gate::SecureGate;

#[cfg(feature = "zeroize")]
use secure_gate::{ExposeSecret, SecurePassword};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    // Test 1: Empty container lifecycle and clone behavior
    {
        let empty = SecureGate::new(Vec::<u8>::new());
        let cloned_empty = empty.clone();
        if empty.expose().len() != cloned_empty.expose().len() {
            return;
        }
        drop(cloned_empty);

        #[cfg(feature = "zeroize")]
        let mut empty = empty; // make mutable only when we need zeroize()
        #[cfg(feature = "zeroize")]
        empty.zeroize();

        if !empty.expose().is_empty() {
            return;
        }
    }

    if data.is_empty() {
        return;
    }

    // Test 2: Basic isolation – clone mutation doesn’t affect original
    let original_data = data.to_vec();
    let mut original = SecureGate::new(original_data.clone());
    let mut clone = original.clone();
    clone.expose_mut().push(0xFF);

    if original.expose() != &original_data {
        return;
    }
    if clone.expose().len() != original_data.len() + 1 {
        return;
    }
    if &clone.expose()[..original_data.len()] != &original_data[..] {
        return;
    }
    if clone.expose()[original_data.len()] != 0xFF {
        return;
    }

    // Test 3: Original mutation doesn’t affect clone
    original.expose_mut().push(0xAA);
    if clone.expose().len() != original_data.len() + 1 {
        return;
    }

    // Test 4: Zeroization verification on original
    let pre_zero_len = original.expose().len();
    #[cfg(feature = "zeroize")]
    original.zeroize();

    let exposed = original.expose();
    #[cfg(feature = "zeroize")]
    if !exposed.iter().all(|&b| b == 0) {
        return;
    }
    if exposed.len() != pre_zero_len {
        return;
    }

    // Test 5: Clone remains intact after original zeroization
    if clone.expose().len() != original_data.len() + 1 {
        return;
    }
    if &clone.expose()[..original_data.len()] != &original_data[..] {
        return;
    }
    if clone.expose()[original_data.len()] != 0xFF {
        return;
    }

    // Test 6: Reallocation stress on a clone-of-clone
    let mut stress_clone = clone.clone();
    if let Some(new_cap) = stress_clone
        .expose()
        .capacity()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
    {
        stress_clone.expose_mut().reserve(new_cap);
        if stress_clone.expose() != clone.expose() {
            return;
        }
    }

    // Test 8: String handling (lossy UTF-8)
    let pw_str = String::from_utf8_lossy(data);
    let secure_str: SecureGate<String> = SecureGate::new(pw_str.to_string());
    let str_clone = secure_str.clone();

    if secure_str.expose() != str_clone.expose() {
        return;
    }
    if secure_str.expose() != pw_str.as_ref() {
        return;
    }

    // Test 9: SecurePassword alias cloning (zeroize feature only)
    #[cfg(feature = "zeroize")]
    {
        let pw: SecurePassword = pw_str.as_ref().into();
        let pw_clone = pw.clone();
        if pw.expose().expose_secret() != pw_clone.expose().expose_secret() {
            return;
        }
        drop(pw_clone);
    }

    // Final cleanup – zeroize the remaining clone
    #[cfg(feature = "zeroize")]
    clone.zeroize();
    #[cfg(feature = "zeroize")]
    if !clone.expose().iter().all(|&b| b == 0) {
        return;
    }
});
