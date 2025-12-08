// ==========================================================================
// tests/fixed_edge_cases_tests.rs
// ==========================================================================
// Comprehensive edge case testing for Fixed type

use secure_gate::Fixed;

// ──────────────────────────────────────────────────────────────
// Fixed::new() edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_new_primitive_types() {
    let u32_val = Fixed::new(42u32);
    assert_eq!(*u32_val.expose_secret(), 42);
    
    let u64_val = Fixed::new(123u64);
    assert_eq!(*u64_val.expose_secret(), 123);
    
    let i32_val = Fixed::new(-42i32);
    assert_eq!(*i32_val.expose_secret(), -42);
}

#[test]
fn fixed_new_empty_array() {
    let key = Fixed::new([0u8; 0]);
    assert_eq!(key.len(), 0);
    assert!(key.is_empty());
}

#[test]
fn fixed_new_single_byte() {
    let key = Fixed::new([42u8]);
    assert_eq!(key.len(), 1);
    assert!(!key.is_empty());
    assert_eq!(*key.expose_secret(), [42u8]);
}

#[test]
fn fixed_new_different_sizes() {
    let key8 = Fixed::new([0u8; 8]);
    let key16 = Fixed::new([0u8; 16]);
    let key32 = Fixed::new([0u8; 32]);
    let key64 = Fixed::new([0u8; 64]);
    
    assert_eq!(key8.len(), 8);
    assert_eq!(key16.len(), 16);
    assert_eq!(key32.len(), 32);
    assert_eq!(key64.len(), 64);
}

#[test]
fn fixed_new_very_large() {
    let key = Fixed::new([0u8; 4096]);
    assert_eq!(key.len(), 4096);
}

// ──────────────────────────────────────────────────────────────
// Fixed::from_slice() edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_from_slice_exact_match() {
    let bytes = &[1u8, 2, 3, 4];
    let key = Fixed::<[u8; 4]>::from_slice(bytes);
    assert_eq!(key.expose_secret(), &[1, 2, 3, 4]);
}

#[test]
fn fixed_from_slice_empty() {
    let bytes = &[];
    let key = Fixed::<[u8; 0]>::from_slice(bytes);
    assert_eq!(key.len(), 0);
    assert!(key.is_empty());
}

#[test]
fn fixed_from_slice_single_byte() {
    let bytes = &[42u8];
    let key = Fixed::<[u8; 1]>::from_slice(bytes);
    assert_eq!(*key.expose_secret(), [42u8]);
}

#[test]
fn fixed_from_slice_large() {
    let bytes: Vec<u8> = (0..32).collect();
    let key = Fixed::<[u8; 32]>::from_slice(&bytes);
    for i in 0..32 {
        assert_eq!(key.expose_secret()[i], i as u8);
    }
}

#[test]
#[should_panic(expected = "slice length mismatch")]
fn fixed_from_slice_too_short() {
    let bytes = &[1u8, 2];
    let _key = Fixed::<[u8; 4]>::from_slice(bytes);
}

#[test]
#[should_panic(expected = "slice length mismatch")]
fn fixed_from_slice_too_long() {
    let bytes = &[1u8, 2, 3, 4, 5];
    let _key = Fixed::<[u8; 4]>::from_slice(bytes);
}

#[test]
#[should_panic(expected = "slice length mismatch")]
fn fixed_from_slice_empty_when_expected_size() {
    let bytes = &[];
    let _key = Fixed::<[u8; 4]>::from_slice(bytes);
}

// ──────────────────────────────────────────────────────────────
// From<[u8; N]> edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_from_array_empty() {
    let key: Fixed<[u8; 0]> = [].into();
    assert_eq!(key.len(), 0);
    assert!(key.is_empty());
}

#[test]
fn fixed_from_array_single_byte() {
    let key: Fixed<[u8; 1]> = [42u8].into();
    assert_eq!(*key.expose_secret(), [42u8]);
}

#[test]
fn fixed_from_array_different_sizes() {
    let key8: Fixed<[u8; 8]> = [0u8; 8].into();
    let key16: Fixed<[u8; 16]> = [0u8; 16].into();
    let key32: Fixed<[u8; 32]> = [0u8; 32].into();
    
    assert_eq!(key8.len(), 8);
    assert_eq!(key16.len(), 16);
    assert_eq!(key32.len(), 32);
}

#[test]
fn fixed_from_array_preserves_data() {
    let arr = [1u8, 2, 3, 4, 5];
    let key: Fixed<[u8; 5]> = arr.into();
    assert_eq!(key.expose_secret(), &[1, 2, 3, 4, 5]);
}

// ──────────────────────────────────────────────────────────────
// expose_secret() and expose_secret_mut() edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_expose_secret_borrowing() {
    let key = Fixed::new([42u8; 32]);
    
    // Can borrow immutably multiple times
    let ref1 = key.expose_secret();
    let ref2 = key.expose_secret();
    assert_eq!(ref1[0], ref2[0]);
}

#[test]
fn fixed_expose_secret_mut_exclusive() {
    let mut key = Fixed::new([42u8; 32]);
    
    // Can borrow mutably (exclusive)
    let mut_ref = key.expose_secret_mut();
    mut_ref[0] = 99;
    assert_eq!(key.expose_secret()[0], 99);
}

#[test]
fn fixed_expose_secret_partial_mutation() {
    let mut key = Fixed::new([0u8; 32]);
    
    // Mutate first half
    for i in 0..16 {
        key.expose_secret_mut()[i] = i as u8;
    }
    
    // Verify first half changed
    for i in 0..16 {
        assert_eq!(key.expose_secret()[i], i as u8);
    }
    
    // Verify second half unchanged
    for i in 16..32 {
        assert_eq!(key.expose_secret()[i], 0);
    }
}

#[test]
fn fixed_expose_secret_all_bytes() {
    let mut key = Fixed::new([0u8; 32]);
    
    // Set all bytes to different values
    for i in 0..32 {
        key.expose_secret_mut()[i] = i as u8;
    }
    
    // Verify all bytes
    for i in 0..32 {
        assert_eq!(key.expose_secret()[i], i as u8);
    }
}

// ──────────────────────────────────────────────────────────────
// len() and is_empty() edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_len_all_sizes() {
    assert_eq!(Fixed::new([0u8; 0]).len(), 0);
    assert_eq!(Fixed::new([0u8; 1]).len(), 1);
    assert_eq!(Fixed::new([0u8; 8]).len(), 8);
    assert_eq!(Fixed::new([0u8; 16]).len(), 16);
    assert_eq!(Fixed::new([0u8; 32]).len(), 32);
    assert_eq!(Fixed::new([0u8; 64]).len(), 64);
    assert_eq!(Fixed::new([0u8; 128]).len(), 128);
}

#[test]
fn fixed_is_empty_all_sizes() {
    assert!(Fixed::new([0u8; 0]).is_empty());
    assert!(!Fixed::new([0u8; 1]).is_empty());
    assert!(!Fixed::new([0u8; 8]).is_empty());
    assert!(!Fixed::new([0u8; 32]).is_empty());
}

// ──────────────────────────────────────────────────────────────
// Clone edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_clone_preserves_data() {
    let key1 = Fixed::new([42u8; 32]);
    let key2 = key1.clone();
    
    // Both should have same data
    assert_eq!(*key1.expose_secret(), *key2.expose_secret());
}

#[test]
fn fixed_clone_isolation() {
    let key1 = Fixed::new([42u8; 32]);
    let mut key2 = key1.clone();
    
    // Mutating clone shouldn't affect original
    key2.expose_secret_mut()[0] = 99;
    
    assert_eq!(key1.expose_secret()[0], 42);
    assert_eq!(key2.expose_secret()[0], 99);
}

#[test]
fn fixed_clone_all_sizes() {
    let key8_1 = Fixed::new([42u8; 8]);
    let key8_2 = key8_1.clone();
    assert_eq!(*key8_1.expose_secret(), *key8_2.expose_secret());
    
    let key32_1 = Fixed::new([42u8; 32]);
    let key32_2 = key32_1.clone();
    assert_eq!(*key32_1.expose_secret(), *key32_2.expose_secret());
}

#[test]
fn fixed_clone_empty() {
    let key1 = Fixed::new([0u8; 0]);
    let key2 = key1.clone();
    assert_eq!(key1.len(), 0);
    assert_eq!(key2.len(), 0);
}

// ──────────────────────────────────────────────────────────────
// Debug redaction edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_debug_redacted_all_sizes() {
    let key0 = Fixed::new([0u8; 0]);
    let key1 = Fixed::new([0u8; 1]);
    let key32 = Fixed::new([0u8; 32]);
    let key1024 = Fixed::new([0u8; 1024]);
    
    assert_eq!(format!("{key0:?}"), "[REDACTED]");
    assert_eq!(format!("{key1:?}"), "[REDACTED]");
    assert_eq!(format!("{key32:?}"), "[REDACTED]");
    assert_eq!(format!("{key1024:?}"), "[REDACTED]");
}

#[test]
fn fixed_debug_redacted_alternate_format() {
    let key = Fixed::new([42u8; 32]);
    assert_eq!(format!("{key:?}"), "[REDACTED]");
    assert_eq!(format!("{key:#?}"), "[REDACTED]");
}

#[test]
fn fixed_debug_redacted_primitive_types() {
    let u32_val = Fixed::new(42u32);
    let u64_val = Fixed::new(123u64);
    
    assert_eq!(format!("{u32_val:?}"), "[REDACTED]");
    assert_eq!(format!("{u64_val:?}"), "[REDACTED]");
}

// ──────────────────────────────────────────────────────────────
// Zero-cost verification edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_zero_cost_all_sizes() {
    let key8 = Fixed::new([0u8; 8]);
    let key16 = Fixed::new([0u8; 16]);
    let key32 = Fixed::new([0u8; 32]);
    let key64 = Fixed::new([0u8; 64]);
    
    assert_eq!(core::mem::size_of_val(&key8), 8);
    assert_eq!(core::mem::size_of_val(&key16), 16);
    assert_eq!(core::mem::size_of_val(&key32), 32);
    assert_eq!(core::mem::size_of_val(&key64), 64);
}

#[test]
fn fixed_zero_cost_primitive_types() {
    let u32_val = Fixed::new(42u32);
    let u64_val = Fixed::new(123u64);
    
    assert_eq!(core::mem::size_of_val(&u32_val), 4);
    assert_eq!(core::mem::size_of_val(&u64_val), 8);
}

// ──────────────────────────────────────────────────────────────
// ct_eq() edge cases (feature-gated)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "conversions")]
#[test]
fn fixed_ct_eq_same_values() {
    let key1 = Fixed::new([42u8; 32]);
    let key2 = Fixed::new([42u8; 32]);
    
    assert!(key1.ct_eq(&key2));
}

#[cfg(feature = "conversions")]
#[test]
fn fixed_ct_eq_different_values() {
    let key1 = Fixed::new([42u8; 32]);
    let key2 = Fixed::new([99u8; 32]);
    
    assert!(!key1.ct_eq(&key2));
}

#[cfg(feature = "conversions")]
#[test]
fn fixed_ct_eq_one_byte_different() {
    let key1 = Fixed::new([42u8; 32]);
    let mut arr = [42u8; 32];
    arr[0] = 99;
    let key2 = Fixed::new(arr);
    
    assert!(!key1.ct_eq(&key2));
}

#[cfg(feature = "conversions")]
#[test]
fn fixed_ct_eq_last_byte_different() {
    let key1 = Fixed::new([42u8; 32]);
    let mut arr = [42u8; 32];
    arr[31] = 99;
    let key2 = Fixed::new(arr);
    
    assert!(!key1.ct_eq(&key2));
}

#[cfg(feature = "conversions")]
#[test]
fn fixed_ct_eq_all_zeros() {
    let key1 = Fixed::new([0u8; 32]);
    let key2 = Fixed::new([0u8; 32]);
    let key3 = Fixed::new([0xFFu8; 32]);
    
    assert!(key1.ct_eq(&key2));
    assert!(!key1.ct_eq(&key3));
}

#[cfg(feature = "conversions")]
#[test]
fn fixed_ct_eq_empty() {
    let key1 = Fixed::new([0u8; 0]);
    let key2 = Fixed::new([0u8; 0]);
    
    assert!(key1.ct_eq(&key2));
}

#[cfg(feature = "conversions")]
#[test]
fn fixed_ct_eq_single_byte() {
    let key1 = Fixed::new([42u8]);
    let key2 = Fixed::new([42u8]);
    let key3 = Fixed::new([99u8]);
    
    assert!(key1.ct_eq(&key2));
    assert!(!key1.ct_eq(&key3));
}

#[cfg(feature = "conversions")]
#[test]
fn fixed_ct_eq_different_sizes() {
    let key8 = Fixed::new([42u8; 8]);
    let key16 = Fixed::new([42u8; 16]);
    let key32 = Fixed::new([42u8; 32]);
    
    // Different sizes should not be comparable via ct_eq
    // (This would be a compile error if we tried, but we test the method exists)
    assert!(key8.ct_eq(&Fixed::new([42u8; 8])));
    assert!(key16.ct_eq(&Fixed::new([42u8; 16])));
    assert!(key32.ct_eq(&Fixed::new([42u8; 32])));
}

// ──────────────────────────────────────────────────────────────
// generate_random() edge cases (feature-gated)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "rand")]
#[test]
fn fixed_generate_random_different_sizes() {
    let key8: Fixed<[u8; 8]> = Fixed::generate_random();
    let key16: Fixed<[u8; 16]> = Fixed::generate_random();
    let key32: Fixed<[u8; 32]> = Fixed::generate_random();
    let key64: Fixed<[u8; 64]> = Fixed::generate_random();
    
    assert_eq!(key8.len(), 8);
    assert_eq!(key16.len(), 16);
    assert_eq!(key32.len(), 32);
    assert_eq!(key64.len(), 64);
    
    // Verify randomness (not all zeros)
    assert!(!key8.expose_secret().iter().all(|&b| b == 0));
    assert!(!key16.expose_secret().iter().all(|&b| b == 0));
    assert!(!key32.expose_secret().iter().all(|&b| b == 0));
    assert!(!key64.expose_secret().iter().all(|&b| b == 0));
}

#[cfg(feature = "rand")]
#[test]
fn fixed_generate_random_empty() {
    let key: Fixed<[u8; 0]> = Fixed::generate_random();
    assert_eq!(key.len(), 0);
    assert!(key.is_empty());
}

#[cfg(feature = "rand")]
#[test]
fn fixed_generate_random_single_byte() {
    let key: Fixed<[u8; 1]> = Fixed::generate_random();
    assert_eq!(key.len(), 1);
    assert!(*key.expose_secret() != [0u8]);
}

#[cfg(feature = "rand")]
#[test]
fn fixed_generate_random_multiple_different() {
    // Generate many values and verify they're all different
    let mut values = Vec::new();
    for _ in 0..100 {
        let key = Fixed::<[u8; 32]>::generate_random();
        values.push(*key.expose_secret());
    }
    
    // Check that all values are unique (extremely unlikely to have duplicates)
    for i in 0..values.len() {
        for j in (i + 1)..values.len() {
            assert_ne!(values[i], values[j], "Duplicate random values found!");
        }
    }
}

#[cfg(feature = "rand")]
#[test]
fn fixed_generate_random_not_all_zeros() {
    let mut all_zero = true;
    for _ in 0..100 {
        let key = Fixed::<[u8; 32]>::generate_random();
        if !key.expose_secret().iter().all(|&b| b == 0) {
            all_zero = false;
            break;
        }
    }
    assert!(!all_zero, "All generated values were zero!");
}

// ──────────────────────────────────────────────────────────────
// Zeroize integration (feature-gated)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "zeroize")]
#[test]
fn fixed_zeroize_preserves_length() {
    use zeroize::Zeroize;
    
    let mut key = Fixed::new([42u8; 32]);
    let original_len = key.len();
    key.zeroize();
    
    // Length should be preserved
    assert_eq!(key.len(), original_len);
    assert_eq!(key.len(), 32);
    
    // But all bytes should be zero
    assert!(key.expose_secret().iter().all(|&b| b == 0));
}

#[cfg(feature = "zeroize")]
#[test]
fn fixed_zeroize_all_sizes() {
    use zeroize::Zeroize;
    
    let mut key8 = Fixed::new([0xFFu8; 8]);
    let mut key16 = Fixed::new([0xFFu8; 16]);
    let mut key32 = Fixed::new([0xFFu8; 32]);
    
    key8.zeroize();
    key16.zeroize();
    key32.zeroize();
    
    assert!(key8.expose_secret().iter().all(|&b| b == 0));
    assert!(key16.expose_secret().iter().all(|&b| b == 0));
    assert!(key32.expose_secret().iter().all(|&b| b == 0));
}

#[cfg(feature = "zeroize")]
#[test]
fn fixed_zeroize_empty() {
    use zeroize::Zeroize;
    
    let mut key = Fixed::new([0u8; 0]);
    key.zeroize();
    
    // Empty array should remain empty
    assert_eq!(key.len(), 0);
    assert!(key.is_empty());
}

#[cfg(feature = "zeroize")]
#[test]
fn fixed_zeroize_partial_data() {
    use zeroize::Zeroize;
    
    let mut key = Fixed::new([1u8, 2, 3, 4, 5]);
    key.zeroize();
    
    // All bytes should be zero
    assert_eq!(*key.expose_secret(), [0u8; 5]);
}

// ──────────────────────────────────────────────────────────────
// no_clone() conversion edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_no_clone_preserves_data() {
    let fixed = Fixed::new([42u8; 32]);
    let no_clone = fixed.no_clone();
    
    assert_eq!(no_clone.expose_secret().len(), 32);
    assert_eq!(no_clone.expose_secret()[0], 42);
}

#[test]
fn fixed_no_clone_all_sizes() {
    let fixed8 = Fixed::new([0u8; 8]);
    let fixed16 = Fixed::new([0u8; 16]);
    let fixed32 = Fixed::new([0u8; 32]);
    
    let no_clone8 = fixed8.no_clone();
    let no_clone16 = fixed16.no_clone();
    let no_clone32 = fixed32.no_clone();
    
    assert_eq!(no_clone8.expose_secret().len(), 8);
    assert_eq!(no_clone16.expose_secret().len(), 16);
    assert_eq!(no_clone32.expose_secret().len(), 32);
}

#[test]
fn fixed_no_clone_empty() {
    let fixed = Fixed::new([0u8; 0]);
    let no_clone = fixed.no_clone();
    
    assert_eq!(no_clone.expose_secret().len(), 0);
    assert!(no_clone.expose_secret().is_empty());
}

// ──────────────────────────────────────────────────────────────
// Real-world integration scenarios
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_workflow_creation_to_usage() {
    // Create from array
    let key: Fixed<[u8; 32]> = [42u8; 32].into();
    
    // Access and verify
    assert_eq!(key.len(), 32);
    assert_eq!(key.expose_secret()[0], 42);
    
    // Mutate
    let mut key_mut = key.clone();
    key_mut.expose_secret_mut()[0] = 99;
    
    // Verify original unchanged
    assert_eq!(key.expose_secret()[0], 42);
    assert_eq!(key_mut.expose_secret()[0], 99);
}

#[test]
fn fixed_workflow_from_slice_to_no_clone() {
    // Create from slice
    let bytes = &[1u8, 2, 3, 4, 5];
    let key = Fixed::<[u8; 5]>::from_slice(bytes);
    
    // Convert to no_clone
    let no_clone = key.no_clone();
    
    // Verify data preserved
    assert_eq!(no_clone.expose_secret(), &[1, 2, 3, 4, 5]);
}

#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn fixed_workflow_random_to_comparison() {
    // Generate random
    let key1: Fixed<[u8; 32]> = Fixed::generate_random();
    let key2: Fixed<[u8; 32]> = Fixed::generate_random();
    
    // Compare (should be different)
    assert!(!key1.ct_eq(&key2));
    
    // Clone and compare (should be same)
    let key1_clone = key1.clone();
    assert!(key1.ct_eq(&key1_clone));
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Pattern filling
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_pattern_fill() {
    let mut key = Fixed::new([0u8; 32]);
    
    // Fill with pattern
    for i in 0..32 {
        key.expose_secret_mut()[i] = (i % 256) as u8;
    }
    
    // Verify pattern
    for i in 0..32 {
        assert_eq!(key.expose_secret()[i], (i % 256) as u8);
    }
}

#[test]
fn fixed_all_zeros() {
    let key = Fixed::new([0u8; 32]);
    assert!(key.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn fixed_all_ones() {
    let key = Fixed::new([0xFFu8; 32]);
    assert!(key.expose_secret().iter().all(|&b| b == 0xFF));
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Maximum reasonable sizes
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_max_reasonable_size() {
    // Test with a reasonably large size (not too large to avoid stack overflow)
    let key = Fixed::new([0u8; 1024]);
    assert_eq!(key.len(), 1024);
    
    // Verify we can access all elements
    assert_eq!(key.expose_secret()[0], 0);
    assert_eq!(key.expose_secret()[1023], 0);
}

