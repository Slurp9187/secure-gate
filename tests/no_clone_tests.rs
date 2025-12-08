// ==========================================================================
// tests/no_clone_tests.rs
// ==========================================================================
// Comprehensive testing for NoClone types

use secure_gate::{Dynamic, DynamicNoClone, Fixed, FixedNoClone};

// ──────────────────────────────────────────────────────────────
// Basic NoClone functionality
// ──────────────────────────────────────────────────────────────

    #[test]
    fn fixed_no_clone_cannot_be_cloned() {
        let _key = FixedNoClone::new([0u8; 32]);
        // _key.clone(); // compile error — correct
    }

    #[test]
    fn fixed_no_clone_has_full_api_parity() {
        let mut key = FixedNoClone::new([42u8; 32]);

        // Use explicit exposure — this is intentional
        assert_eq!(key.expose_secret()[0], 42);
        key.expose_secret_mut()[0] = 99;
        assert_eq!(key.expose_secret()[0], 99);

    // All access must go through expose_secret() — security model enforced
    // Verify first element changed, rest remain 42
    assert_eq!(key.expose_secret()[0], 99);
    assert_eq!(key.expose_secret()[1], 42);
    assert_eq!(key.expose_secret()[31], 42);
    }

    #[test]
    fn from_fixed_to_no_clone_works() {
        let fixed = Fixed::new([1u8; 32]);
        let no_clone = fixed.no_clone();
        assert_eq!(no_clone.expose_secret()[0], 1);
        // no_clone.clone(); // compile error — correct
    }

    #[test]
    fn dynamic_no_clone_string() {
        let mut pw: DynamicNoClone<String> = DynamicNoClone::new(Box::new("secret".to_owned()));

        // Must use expose_secret_mut() — no implicit Deref
        pw.expose_secret_mut().push_str("123");
        assert_eq!(pw.expose_secret(), "secret123");

    // Shrink to fit using explicit exposure
    pw.expose_secret_mut().shrink_to_fit();
    assert_eq!(pw.expose_secret(), "secret123");
    }

    #[test]
    fn dynamic_no_clone_vec_u8() {
        let mut data = DynamicNoClone::new(Box::new(vec![1, 2, 3]));

        data.expose_secret_mut().push(42);
        assert_eq!(data.expose_secret(), &[1, 2, 3, 42]);

    // All access must go through expose_secret() — security model enforced
    assert_eq!(data.expose_secret(), &vec![1, 2, 3, 42]);
}

// ──────────────────────────────────────────────────────────────
// FixedNoClone edge cases: Different sizes
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_no_clone_empty() {
    let key = FixedNoClone::new([0u8; 0]);
    assert_eq!(key.expose_secret().len(), 0);
    assert!(key.expose_secret().is_empty());
}

#[test]
fn fixed_no_clone_single_byte() {
    let mut key = FixedNoClone::new([42u8]);
    assert_eq!(key.expose_secret().len(), 1);
    assert_eq!(*key.expose_secret(), [42u8]);
    
    key.expose_secret_mut()[0] = 99;
    assert_eq!(*key.expose_secret(), [99u8]);
}

#[test]
fn fixed_no_clone_small_sizes() {
    let key8 = FixedNoClone::new([0u8; 8]);
    let key16 = FixedNoClone::new([0u8; 16]);
    let key24 = FixedNoClone::new([0u8; 24]);
    
    assert_eq!(key8.expose_secret().len(), 8);
    assert_eq!(key16.expose_secret().len(), 16);
    assert_eq!(key24.expose_secret().len(), 24);
}

#[test]
fn fixed_no_clone_common_crypto_sizes() {
    let key32 = FixedNoClone::new([0u8; 32]); // AES-256
    let key64 = FixedNoClone::new([0u8; 64]); // 512-bit
    let key128 = FixedNoClone::new([0u8; 128]);
    
    assert_eq!(key32.expose_secret().len(), 32);
    assert_eq!(key64.expose_secret().len(), 64);
    assert_eq!(key128.expose_secret().len(), 128);
}

#[test]
fn fixed_no_clone_very_large() {
    let key = FixedNoClone::new([0u8; 4096]);
    assert_eq!(key.expose_secret().len(), 4096);
}

// ──────────────────────────────────────────────────────────────
// FixedNoClone edge cases: Zero-cost verification
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_no_clone_zero_cost_all_sizes() {
    let key8 = FixedNoClone::new([0u8; 8]);
    let key16 = FixedNoClone::new([0u8; 16]);
    let key32 = FixedNoClone::new([0u8; 32]);
    let key64 = FixedNoClone::new([0u8; 64]);
    
    assert_eq!(core::mem::size_of_val(&key8), 8);
    assert_eq!(core::mem::size_of_val(&key16), 16);
    assert_eq!(core::mem::size_of_val(&key32), 32);
    assert_eq!(core::mem::size_of_val(&key64), 64);
}

// ──────────────────────────────────────────────────────────────
// FixedNoClone edge cases: Debug redaction
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_no_clone_debug_redacted() {
    let key = FixedNoClone::new([42u8; 32]);
    assert_eq!(format!("{key:?}"), "[REDACTED]");
    assert_eq!(format!("{key:#?}"), "[REDACTED]");
}

#[test]
fn fixed_no_clone_debug_redacted_all_sizes() {
    let key0 = FixedNoClone::new([0u8; 0]);
    let key1 = FixedNoClone::new([0u8; 1]);
    let key32 = FixedNoClone::new([0u8; 32]);
    let key1024 = FixedNoClone::new([0u8; 1024]);
    
    assert_eq!(format!("{key0:?}"), "[REDACTED]");
    assert_eq!(format!("{key1:?}"), "[REDACTED]");
    assert_eq!(format!("{key32:?}"), "[REDACTED]");
    assert_eq!(format!("{key1024:?}"), "[REDACTED]");
}

// ──────────────────────────────────────────────────────────────
// FixedNoClone edge cases: Byte array access
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_no_clone_byte_array_access() {
    let mut key = FixedNoClone::new([42u8; 32]);
    
    let slice: &[u8] = key.expose_secret();
    assert_eq!(slice.len(), 32);
    assert_eq!(slice[0], 42);
    assert_eq!(slice[31], 42);
    
    let mut_slice: &mut [u8] = key.expose_secret_mut();
    mut_slice[0] = 99;
    mut_slice[31] = 88;
    
    assert_eq!(key.expose_secret()[0], 99);
    assert_eq!(key.expose_secret()[31], 88);
    assert_eq!(key.expose_secret()[1], 42); // Middle unchanged
}

#[test]
fn fixed_no_clone_partial_mutation() {
    let mut key = FixedNoClone::new([0u8; 32]);
    
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

// ──────────────────────────────────────────────────────────────
// FixedNoClone edge cases: Conversion from Fixed
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_to_no_clone_preserves_all_data() {
    let mut fixed = Fixed::new([1u8, 2, 3, 4, 5, 6, 7, 8]);
    fixed.expose_secret_mut()[0] = 99;
    
    let no_clone = fixed.no_clone();
    
    assert_eq!(no_clone.expose_secret()[0], 99);
    assert_eq!(no_clone.expose_secret()[1], 2);
    assert_eq!(no_clone.expose_secret()[7], 8);
}

#[test]
fn fixed_to_no_clone_different_sizes() {
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
fn fixed_to_no_clone_empty() {
    let fixed = Fixed::new([0u8; 0]);
    let no_clone = fixed.no_clone();
    
    assert_eq!(no_clone.expose_secret().len(), 0);
    assert!(no_clone.expose_secret().is_empty());
}

// ──────────────────────────────────────────────────────────────
// DynamicNoClone edge cases: String
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_no_clone_string_empty() {
    let pw = DynamicNoClone::new(Box::new("".to_string()));
    assert!(pw.is_empty());
    assert_eq!(pw.len(), 0);
    assert_eq!(pw.expose_secret(), "");
}

#[test]
fn dynamic_no_clone_string_single_char() {
    let mut pw = DynamicNoClone::new(Box::new("a".to_string()));
    assert_eq!(pw.len(), 1);
    assert!(!pw.is_empty());
    assert_eq!(pw.expose_secret(), "a");
    
    pw.expose_secret_mut().push('b');
    assert_eq!(pw.expose_secret(), "ab");
}

#[test]
fn dynamic_no_clone_string_unicode() {
    let mut pw = DynamicNoClone::new(Box::new("hello".to_string()));
    pw.expose_secret_mut().push_str(" 世界");
    
    assert_eq!(pw.expose_secret(), "hello 世界");
    // "hello" = 5 bytes, " " = 1 byte, "世界" = 6 bytes (3 bytes per char in UTF-8)
    // Total = 12 bytes
    assert_eq!(pw.len(), 12); // UTF-8 byte length
}

#[test]
fn dynamic_no_clone_string_append_operations() {
    let mut pw = DynamicNoClone::new(Box::new("secret".to_string()));
    
    pw.expose_secret_mut().push('!');
    assert_eq!(pw.expose_secret(), "secret!");
    
    pw.expose_secret_mut().push_str("123");
    assert_eq!(pw.expose_secret(), "secret!123");
    
    pw.expose_secret_mut().clear();
    assert!(pw.is_empty());
    assert_eq!(pw.expose_secret(), "");
}

#[test]
fn dynamic_no_clone_string_shrink_to_fit() {
    let mut pw = DynamicNoClone::new(Box::new("hello".to_string()));
    pw.expose_secret_mut().push_str(" world");
    
    // Shrink to fit after mutation
    pw.expose_secret_mut().shrink_to_fit();
    assert_eq!(pw.expose_secret(), "hello world");
}

// ──────────────────────────────────────────────────────────────
// DynamicNoClone edge cases: Vec<u8>
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_no_clone_vec_empty() {
    let data = DynamicNoClone::new(Box::new(Vec::<u8>::new()));
    assert!(data.is_empty());
    assert_eq!(data.len(), 0);
    assert_eq!(data.expose_secret(), &[]);
}

#[test]
fn dynamic_no_clone_vec_single_element() {
    let mut data = DynamicNoClone::new(Box::new(vec![42u8]));
    assert_eq!(data.len(), 1);
    assert!(!data.is_empty());
    assert_eq!(data.expose_secret(), &[42]);
    
    data.expose_secret_mut()[0] = 99;
    assert_eq!(data.expose_secret(), &[99]);
}

#[test]
fn dynamic_no_clone_vec_small_sizes() {
    let data8 = DynamicNoClone::new(Box::new(vec![0u8; 8]));
    let data16 = DynamicNoClone::new(Box::new(vec![0u8; 16]));
    let data32 = DynamicNoClone::new(Box::new(vec![0u8; 32]));
    
    assert_eq!(data8.len(), 8);
    assert_eq!(data16.len(), 16);
    assert_eq!(data32.len(), 32);
}

#[test]
fn dynamic_no_clone_vec_large() {
    let data = DynamicNoClone::new(Box::new(vec![42u8; 4096]));
    assert_eq!(data.len(), 4096);
    assert_eq!(data.expose_secret()[0], 42);
    assert_eq!(data.expose_secret()[4095], 42);
}

#[test]
fn dynamic_no_clone_vec_push_pop() {
    let mut data = DynamicNoClone::new(Box::new(vec![1, 2, 3]));
    
    data.expose_secret_mut().push(4);
    assert_eq!(data.expose_secret(), &[1, 2, 3, 4]);
    
    let popped = data.expose_secret_mut().pop();
    assert_eq!(popped, Some(4));
    assert_eq!(data.expose_secret(), &[1, 2, 3]);
}

#[test]
fn dynamic_no_clone_vec_partial_mutation() {
    let mut data = DynamicNoClone::new(Box::new(vec![0u8; 32]));
    
    // Mutate first half
    for i in 0..16 {
        data.expose_secret_mut()[i] = i as u8;
    }
    
    // Verify first half changed
    for i in 0..16 {
        assert_eq!(data.expose_secret()[i], i as u8);
    }
    
    // Verify second half unchanged
    for i in 16..32 {
        assert_eq!(data.expose_secret()[i], 0);
    }
}

#[test]
fn dynamic_no_clone_vec_extend() {
    let mut data = DynamicNoClone::new(Box::new(vec![1, 2, 3]));
    
    data.expose_secret_mut().extend_from_slice(&[4, 5, 6]);
    assert_eq!(data.expose_secret(), &[1, 2, 3, 4, 5, 6]);
    
    data.expose_secret_mut().clear();
    assert!(data.is_empty());
}

// ──────────────────────────────────────────────────────────────
// DynamicNoClone edge cases: Debug redaction
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_no_clone_debug_redacted() {
    let pw = DynamicNoClone::new(Box::new("secret".to_string()));
    let data = DynamicNoClone::new(Box::new(vec![1, 2, 3]));
    
    assert_eq!(format!("{pw:?}"), "[REDACTED]");
    assert_eq!(format!("{data:?}"), "[REDACTED]");
    assert_eq!(format!("{pw:#?}"), "[REDACTED]");
    assert_eq!(format!("{data:#?}"), "[REDACTED]");
}

#[test]
fn dynamic_no_clone_debug_redacted_empty() {
    let empty_str = DynamicNoClone::new(Box::new("".to_string()));
    let empty_vec = DynamicNoClone::new(Box::new(Vec::<u8>::new()));
    
    assert_eq!(format!("{empty_str:?}"), "[REDACTED]");
    assert_eq!(format!("{empty_vec:?}"), "[REDACTED]");
}

// ──────────────────────────────────────────────────────────────
// DynamicNoClone edge cases: Conversion from Dynamic
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_to_no_clone_string_preserves_data() {
    let mut dynamic = Dynamic::<String>::new("hello".to_string());
    dynamic.expose_secret_mut().push('!');
    
    let no_clone = dynamic.no_clone();
    
    assert_eq!(no_clone.expose_secret(), "hello!");
    assert_eq!(no_clone.len(), 6);
}

#[test]
fn dynamic_to_no_clone_vec_preserves_data() {
    let mut dynamic = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    dynamic.expose_secret_mut().push(4);
    
    let no_clone = dynamic.no_clone();
    
    assert_eq!(no_clone.expose_secret(), &[1, 2, 3, 4]);
    assert_eq!(no_clone.len(), 4);
}

#[test]
fn dynamic_to_no_clone_empty() {
    let empty_str = Dynamic::<String>::new("".to_string());
    let empty_vec = Dynamic::<Vec<u8>>::new(Vec::new());
    
    let no_clone_str = empty_str.no_clone();
    let no_clone_vec = empty_vec.no_clone();
    
    assert!(no_clone_str.is_empty());
    assert!(no_clone_vec.is_empty());
    assert_eq!(no_clone_str.len(), 0);
    assert_eq!(no_clone_vec.len(), 0);
}

// ──────────────────────────────────────────────────────────────
// Zeroize integration (when feature enabled)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "zeroize")]
#[test]
fn fixed_no_clone_zeroize() {
    use zeroize::Zeroize;
    
    let mut key = FixedNoClone::new([42u8; 32]);
    key.zeroize();
    
    // After zeroize, should be all zeros
    assert!(key.expose_secret().iter().all(|&b| b == 0));
}

#[cfg(feature = "zeroize")]
#[test]
fn fixed_no_clone_zeroize_preserves_length() {
    use zeroize::Zeroize;
    
    let mut key = FixedNoClone::new([42u8; 32]);
    let original_len = key.expose_secret().len();
    key.zeroize();
    
    // Length should be preserved
    assert_eq!(key.expose_secret().len(), original_len);
    assert_eq!(key.expose_secret().len(), 32);
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_no_clone_string_zeroize() {
    use zeroize::Zeroize;
    
    let mut pw = DynamicNoClone::new(Box::new("secret".to_string()));
    pw.zeroize();
    
    // After zeroize, String is cleared
    assert!(pw.is_empty());
    assert_eq!(pw.expose_secret(), "");
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_no_clone_vec_zeroize() {
    use zeroize::Zeroize;
    
    let mut data = DynamicNoClone::new(Box::new(vec![42u8; 32]));
    let original_len = data.len();
    data.zeroize();
    
    // After zeroize, Vec is cleared
    assert!(data.is_empty());
    assert_eq!(data.len(), 0);
    assert_ne!(original_len, 0); // Verify it was non-empty before
}

// ──────────────────────────────────────────────────────────────
// zeroize_now() explicit zeroization
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "zeroize")]
#[test]
fn fixed_no_clone_zeroize_now() {
    let mut key = FixedNoClone::new([42u8; 32]);
    assert_eq!(key.expose_secret()[0], 42);
    
    key.zeroize_now();
    
    // After zeroize_now, should be all zeros
    assert!(key.expose_secret().iter().all(|&b| b == 0));
    assert_eq!(key.expose_secret().len(), 32); // Length preserved
}

#[cfg(feature = "zeroize")]
#[test]
fn fixed_no_clone_zeroize_now_preserves_length() {
    let mut key = FixedNoClone::new([0xFFu8; 64]);
    let original_len = key.expose_secret().len();
    
    key.zeroize_now();
    
    assert_eq!(key.expose_secret().len(), original_len);
    assert!(key.expose_secret().iter().all(|&b| b == 0));
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_no_clone_zeroize_now_string() {
    let mut password = DynamicNoClone::new(Box::new("secret".to_string()));
    assert_eq!(password.expose_secret(), "secret");
    
    password.zeroize_now();
    
    // After zeroize_now, String should be empty
    assert!(password.is_empty());
    assert_eq!(password.expose_secret(), "");
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_no_clone_zeroize_now_vec() {
    let mut data = DynamicNoClone::new(Box::new(vec![42u8; 32]));
    assert_eq!(data.len(), 32);
    
    data.zeroize_now();
    
    // After zeroize_now, Vec should be empty
    assert!(data.is_empty());
    assert_eq!(data.len(), 0);
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_no_clone_zeroize_now_empty() {
    let mut empty_str = DynamicNoClone::new(Box::new("".to_string()));
    let mut empty_vec = DynamicNoClone::new(Box::new(Vec::<u8>::new()));
    
    empty_str.zeroize_now();
    empty_vec.zeroize_now();
    
    assert!(empty_str.is_empty());
    assert!(empty_vec.is_empty());
}

// ──────────────────────────────────────────────────────────────
// Real-world integration scenarios
// ──────────────────────────────────────────────────────────────

#[test]
fn no_clone_types_together() {
    let fixed_no_clone = FixedNoClone::new([42u8; 32]);
    let dynamic_no_clone_str = DynamicNoClone::new(Box::new("secret".to_string()));
    let dynamic_no_clone_vec = DynamicNoClone::new(Box::new(vec![1, 2, 3]));
    
    // All should work independently
    assert_eq!(fixed_no_clone.expose_secret().len(), 32);
    assert_eq!(dynamic_no_clone_str.len(), 6);
    assert_eq!(dynamic_no_clone_vec.len(), 3);
}

#[test]
fn conversion_chain_fixed_to_no_clone() {
    let fixed = Fixed::new([42u8; 32]);
    let no_clone = fixed.no_clone();
    
    // Can still access data
    assert_eq!(no_clone.expose_secret()[0], 42);
    
    // But cannot clone
    // let _cloned = no_clone.clone(); // compile error — correct
}

#[test]
fn conversion_chain_dynamic_to_no_clone() {
    let dynamic = Dynamic::<String>::new("secret".to_string());
    let no_clone = dynamic.no_clone();
    
    // Can still access data
    assert_eq!(no_clone.expose_secret(), "secret");
    
    // But cannot clone
    // let _cloned = no_clone.clone(); // compile error — correct
}

#[cfg(feature = "rand")]
#[test]
fn rng_to_fixed_to_no_clone_chain() {
    use secure_gate::rng::FixedRng;
    
    // Chain: RNG -> Fixed -> FixedNoClone
    let rng = FixedRng::<32>::generate();
    let fixed: Fixed<[u8; 32]> = rng.into();
    let no_clone = fixed.no_clone();
    
    assert_eq!(no_clone.expose_secret().len(), 32);
    assert!(!no_clone.expose_secret().iter().all(|&b| b == 0));
}

#[cfg(feature = "rand")]
#[test]
fn rng_to_dynamic_to_no_clone_chain() {
    use secure_gate::rng::DynamicRng;
    
    // Chain: RNG -> Dynamic -> DynamicNoClone
    let rng = DynamicRng::generate(64);
    let dynamic: Dynamic<Vec<u8>> = rng.into();
    let no_clone = dynamic.no_clone();
    
    assert_eq!(no_clone.len(), 64);
    assert!(!no_clone.expose_secret().iter().all(|&b| b == 0));
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Ownership and borrowing
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_no_clone_borrowing() {
    let mut key = FixedNoClone::new([42u8; 32]);
    
    // Can borrow immutably multiple times
    let ref1 = key.expose_secret();
    let ref2 = key.expose_secret();
    assert_eq!(ref1[0], ref2[0]);
    
    // Can borrow mutably (exclusive)
    let mut_ref = key.expose_secret_mut();
    mut_ref[0] = 99;
    assert_eq!(key.expose_secret()[0], 99);
}

#[test]
fn dynamic_no_clone_borrowing() {
    let mut pw = DynamicNoClone::new(Box::new("secret".to_string()));
    
    // Can borrow immutably multiple times
    let ref1 = pw.expose_secret();
    let ref2 = pw.expose_secret();
    assert_eq!(ref1, ref2);
    
    // Can borrow mutably (exclusive)
    let mut_ref = pw.expose_secret_mut();
    mut_ref.push('!');
    assert_eq!(pw.expose_secret(), "secret!");
}

// ──────────────────────────────────────────────────────────────
// Edge cases: All zeros and all ones
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_no_clone_all_zeros() {
    let key = FixedNoClone::new([0u8; 32]);
    assert!(key.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn fixed_no_clone_all_ones() {
    let key = FixedNoClone::new([0xFFu8; 32]);
    assert!(key.expose_secret().iter().all(|&b| b == 0xFF));
}

#[test]
fn dynamic_no_clone_vec_all_zeros() {
    let data = DynamicNoClone::new(Box::new(vec![0u8; 32]));
    assert!(data.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn dynamic_no_clone_vec_all_ones() {
    let data = DynamicNoClone::new(Box::new(vec![0xFFu8; 32]));
    assert!(data.expose_secret().iter().all(|&b| b == 0xFF));
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Pattern filling
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_no_clone_pattern_fill() {
    let mut key = FixedNoClone::new([0u8; 32]);
    
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
fn dynamic_no_clone_vec_pattern_fill() {
    let mut data = DynamicNoClone::new(Box::new(vec![0u8; 32]));
    
    // Fill with pattern
    for i in 0..32 {
        data.expose_secret_mut()[i] = (i % 256) as u8;
    }
    
    // Verify pattern
    for i in 0..32 {
        assert_eq!(data.expose_secret()[i], (i % 256) as u8);
    }
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Concurrent access patterns
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_no_clone_read_then_write() {
    let mut key = FixedNoClone::new([42u8; 32]);
    
    // Read first
    let initial = *key.expose_secret();
    assert_eq!(initial[0], 42);
    
    // Then write
    key.expose_secret_mut()[0] = 99;
    assert_eq!(key.expose_secret()[0], 99);
}

#[test]
fn dynamic_no_clone_read_then_write() {
    let mut pw = DynamicNoClone::new(Box::new("hello".to_string()));
    
    // Read first
    let initial = pw.expose_secret().clone();
    assert_eq!(initial, "hello");
    
    // Then write
    pw.expose_secret_mut().push_str(" world");
    assert_eq!(pw.expose_secret(), "hello world");
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Maximum sizes (stress test)
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_no_clone_max_reasonable_size() {
    // Test with a reasonably large size (not too large to avoid stack overflow)
    let key = FixedNoClone::new([0u8; 1024]);
    assert_eq!(key.expose_secret().len(), 1024);
    
    // Verify we can access all elements
    assert_eq!(key.expose_secret()[0], 0);
    assert_eq!(key.expose_secret()[1023], 0);
}

#[test]
fn dynamic_no_clone_vec_max_reasonable_size() {
    // Test with a reasonably large size
    let data = DynamicNoClone::new(Box::new(vec![42u8; 1024]));
    assert_eq!(data.len(), 1024);
    
    // Verify we can access all elements
    assert_eq!(data.expose_secret()[0], 42);
    assert_eq!(data.expose_secret()[1023], 42);
}
