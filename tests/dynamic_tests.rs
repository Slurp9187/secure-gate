// ==========================================================================
// tests/dynamic_edge_cases_tests.rs
// ==========================================================================
// Comprehensive edge case testing for Dynamic type

use secure_gate::Dynamic;

// ──────────────────────────────────────────────────────────────
// Dynamic::new() edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_new_string_empty() {
    let pw = Dynamic::<String>::new("".to_string());
    assert!(pw.is_empty());
    assert_eq!(pw.len(), 0);
    assert_eq!(pw.expose_secret(), "");
}

#[test]
fn dynamic_new_string_single_char() {
    let pw = Dynamic::<String>::new("a".to_string());
    assert_eq!(pw.len(), 1);
    assert!(!pw.is_empty());
    assert_eq!(pw.expose_secret(), "a");
}

#[test]
fn dynamic_new_string_unicode() {
    let pw = Dynamic::<String>::new("hello 世界".to_string());
    assert_eq!(pw.expose_secret(), "hello 世界");
    // UTF-8 byte length: "hello " = 6, "世界" = 6 (3 bytes each)
    assert_eq!(pw.len(), 12);
}

#[test]
fn dynamic_new_vec_u8_empty() {
    let data = Dynamic::<Vec<u8>>::new(Vec::new());
    assert!(data.is_empty());
    assert_eq!(data.len(), 0);
    assert_eq!(data.expose_secret(), &[]);
}

#[test]
fn dynamic_new_vec_u8_single_element() {
    let data = Dynamic::<Vec<u8>>::new(vec![42u8]);
    assert_eq!(data.len(), 1);
    assert!(!data.is_empty());
    assert_eq!(data.expose_secret(), &[42]);
}

#[test]
fn dynamic_new_vec_u8_small() {
    let data = Dynamic::<Vec<u8>>::new(vec![1, 2, 3, 4]);
    assert_eq!(data.len(), 4);
    assert_eq!(data.expose_secret(), &[1, 2, 3, 4]);
}

#[test]
fn dynamic_new_vec_u8_large() {
    let data = Dynamic::<Vec<u8>>::new(vec![42u8; 4096]);
    assert_eq!(data.len(), 4096);
    assert_eq!(data.expose_secret()[0], 42);
    assert_eq!(data.expose_secret()[4095], 42);
}

#[test]
fn dynamic_new_vec_other_types() {
    let ints = Dynamic::<Vec<i32>>::new(vec![1, 2, 3]);
    assert_eq!(ints.len(), 3);
    assert_eq!(ints.expose_secret(), &[1, 2, 3]);
}

// ──────────────────────────────────────────────────────────────
// Dynamic::new_boxed() edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_new_boxed_string() {
    let boxed = Box::new("secret".to_string());
    let pw = Dynamic::<String>::new_boxed(boxed);
    assert_eq!(pw.expose_secret(), "secret");
}

#[test]
fn dynamic_new_boxed_vec() {
    let boxed = Box::new(vec![1, 2, 3]);
    let data = Dynamic::<Vec<u8>>::new_boxed(boxed);
    assert_eq!(data.expose_secret(), &[1, 2, 3]);
}

#[test]
fn dynamic_new_boxed_empty() {
    let boxed_str = Box::new("".to_string());
    let boxed_vec = Box::new(Vec::<u8>::new());
    
    let pw = Dynamic::<String>::new_boxed(boxed_str);
    let data = Dynamic::<Vec<u8>>::new_boxed(boxed_vec);
    
    assert!(pw.is_empty());
    assert!(data.is_empty());
}

// ──────────────────────────────────────────────────────────────
// expose_secret() and expose_secret_mut() edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_expose_secret_borrowing() {
    let pw = Dynamic::<String>::new("secret".to_string());
    
    // Can borrow immutably multiple times
    let ref1 = pw.expose_secret();
    let ref2 = pw.expose_secret();
    assert_eq!(ref1, ref2);
}

#[test]
fn dynamic_expose_secret_mut_exclusive() {
    let mut pw = Dynamic::<String>::new("hello".to_string());
    
    // Can borrow mutably (exclusive)
    let mut_ref = pw.expose_secret_mut();
    mut_ref.push_str(" world");
    assert_eq!(pw.expose_secret(), "hello world");
}

#[test]
fn dynamic_expose_secret_string_mutations() {
    let mut pw = Dynamic::<String>::new("hello".to_string());
    
    pw.expose_secret_mut().push('!');
    assert_eq!(pw.expose_secret(), "hello!");
    
    pw.expose_secret_mut().push_str("123");
    assert_eq!(pw.expose_secret(), "hello!123");
    
    pw.expose_secret_mut().clear();
    assert!(pw.is_empty());
}

#[test]
fn dynamic_expose_secret_vec_mutations() {
    let mut data = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    
    data.expose_secret_mut().push(4);
    assert_eq!(data.expose_secret(), &[1, 2, 3, 4]);
    
    data.expose_secret_mut().extend_from_slice(&[5, 6]);
    assert_eq!(data.expose_secret(), &[1, 2, 3, 4, 5, 6]);
    
    data.expose_secret_mut().clear();
    assert!(data.is_empty());
}

#[test]
fn dynamic_expose_secret_vec_partial_mutation() {
    let mut data = Dynamic::<Vec<u8>>::new(vec![0u8; 32]);
    
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

// ──────────────────────────────────────────────────────────────
// len() and is_empty() edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_string_len_is_empty() {
    let empty = Dynamic::<String>::new("".to_string());
    let single = Dynamic::<String>::new("a".to_string());
    let normal = Dynamic::<String>::new("hello".to_string());
    let unicode = Dynamic::<String>::new("世界".to_string());
    
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    
    assert!(!single.is_empty());
    assert_eq!(single.len(), 1);
    
    assert!(!normal.is_empty());
    assert_eq!(normal.len(), 5);
    
    assert!(!unicode.is_empty());
    assert_eq!(unicode.len(), 6); // UTF-8: 3 bytes per char
}

#[test]
fn dynamic_vec_len_is_empty() {
    let empty = Dynamic::<Vec<u8>>::new(Vec::new());
    let single = Dynamic::<Vec<u8>>::new(vec![42u8]);
    let small = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    let large = Dynamic::<Vec<u8>>::new(vec![0u8; 1024]);
    
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    
    assert!(!single.is_empty());
    assert_eq!(single.len(), 1);
    
    assert!(!small.is_empty());
    assert_eq!(small.len(), 3);
    
    assert!(!large.is_empty());
    assert_eq!(large.len(), 1024);
}

// ──────────────────────────────────────────────────────────────
// From implementations edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_from_string() {
    let pw: Dynamic<String> = "secret".into();
    assert_eq!(pw.expose_secret(), "secret");
}

#[test]
fn dynamic_from_str() {
    let pw: Dynamic<String> = "hunter2".into();
    assert_eq!(pw.expose_secret(), "hunter2");
}

#[test]
fn dynamic_from_vec() {
    let data: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    assert_eq!(data.expose_secret(), &[1, 2, 3]);
}

#[test]
fn dynamic_from_box() {
    let boxed = Box::new("secret".to_string());
    let pw: Dynamic<String> = boxed.into();
    assert_eq!(pw.expose_secret(), "secret");
    
    let boxed_vec = Box::new(vec![1, 2, 3]);
    let data: Dynamic<Vec<u8>> = boxed_vec.into();
    assert_eq!(data.expose_secret(), &[1, 2, 3]);
}

#[test]
fn dynamic_from_empty() {
    let empty_str: Dynamic<String> = "".into();
    let empty_vec: Dynamic<Vec<u8>> = Vec::new().into();
    
    assert!(empty_str.is_empty());
    assert!(empty_vec.is_empty());
}

#[test]
fn dynamic_from_unicode_str() {
    let pw: Dynamic<String> = "hello 世界".into();
    assert_eq!(pw.expose_secret(), "hello 世界");
    assert_eq!(pw.len(), 12); // UTF-8 byte length
}

// ──────────────────────────────────────────────────────────────
// Clone edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_clone_string_preserves_data() {
    let pw1 = Dynamic::<String>::new("secret".to_string());
    let pw2 = pw1.clone();
    
    assert_eq!(pw1.expose_secret(), pw2.expose_secret());
    assert_eq!(pw1.expose_secret(), "secret");
}

#[test]
fn dynamic_clone_string_isolation() {
    let pw1 = Dynamic::<String>::new("original".to_string());
    let mut pw2 = pw1.clone();
    
    // Mutating clone shouldn't affect original
    pw2.expose_secret_mut().push('!');
    
    assert_eq!(pw1.expose_secret(), "original");
    assert_eq!(pw2.expose_secret(), "original!");
}

#[test]
fn dynamic_clone_vec_preserves_data() {
    let data1 = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    let data2 = data1.clone();
    
    assert_eq!(data1.expose_secret(), data2.expose_secret());
    assert_eq!(data1.expose_secret(), &[1, 2, 3]);
}

#[test]
fn dynamic_clone_vec_isolation() {
    let data1 = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    let mut data2 = data1.clone();
    
    // Mutating clone shouldn't affect original
    data2.expose_secret_mut().push(4);
    
    assert_eq!(data1.expose_secret(), &[1, 2, 3]);
    assert_eq!(data2.expose_secret(), &[1, 2, 3, 4]);
}

#[test]
fn dynamic_clone_empty() {
    let empty_str1 = Dynamic::<String>::new("".to_string());
    let empty_str2 = empty_str1.clone();
    
    let empty_vec1 = Dynamic::<Vec<u8>>::new(Vec::new());
    let empty_vec2 = empty_vec1.clone();
    
    assert!(empty_str1.is_empty());
    assert!(empty_str2.is_empty());
    assert!(empty_vec1.is_empty());
    assert!(empty_vec2.is_empty());
}

#[test]
fn dynamic_clone_large() {
    let large1 = Dynamic::<Vec<u8>>::new(vec![42u8; 1024]);
    let large2 = large1.clone();
    
    assert_eq!(large1.len(), 1024);
    assert_eq!(large2.len(), 1024);
    assert_eq!(large1.expose_secret()[0], large2.expose_secret()[0]);
}

// ──────────────────────────────────────────────────────────────
// Debug redaction edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_debug_redacted_string() {
    let pw = Dynamic::<String>::new("secret".to_string());
    assert_eq!(format!("{pw:?}"), "[REDACTED]");
    assert_eq!(format!("{pw:#?}"), "[REDACTED]");
}

#[test]
fn dynamic_debug_redacted_vec() {
    let data = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    assert_eq!(format!("{data:?}"), "[REDACTED]");
    assert_eq!(format!("{data:#?}"), "[REDACTED]");
}

#[test]
fn dynamic_debug_redacted_empty() {
    let empty_str = Dynamic::<String>::new("".to_string());
    let empty_vec = Dynamic::<Vec<u8>>::new(Vec::new());
    
    assert_eq!(format!("{empty_str:?}"), "[REDACTED]");
    assert_eq!(format!("{empty_vec:?}"), "[REDACTED]");
}

#[test]
fn dynamic_debug_redacted_large() {
    let large = Dynamic::<Vec<u8>>::new(vec![42u8; 4096]);
    assert_eq!(format!("{large:?}"), "[REDACTED]");
}

// ──────────────────────────────────────────────────────────────
// ct_eq() edge cases (feature-gated)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "conversions")]
#[test]
fn dynamic_ct_eq_string_same() {
    let pw1 = Dynamic::<String>::new("secret".to_string());
    let pw2 = Dynamic::<String>::new("secret".to_string());
    
    assert!(pw1.ct_eq(&pw2));
}

#[cfg(feature = "conversions")]
#[test]
fn dynamic_ct_eq_string_different() {
    let pw1 = Dynamic::<String>::new("secret".to_string());
    let pw2 = Dynamic::<String>::new("password".to_string());
    
    assert!(!pw1.ct_eq(&pw2));
}

#[cfg(feature = "conversions")]
#[test]
fn dynamic_ct_eq_vec_same() {
    let data1 = Dynamic::<Vec<u8>>::new(vec![1, 2, 3, 4]);
    let data2 = Dynamic::<Vec<u8>>::new(vec![1, 2, 3, 4]);
    
    assert!(data1.ct_eq(&data2));
}

#[cfg(feature = "conversions")]
#[test]
fn dynamic_ct_eq_vec_different() {
    let data1 = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    let data2 = Dynamic::<Vec<u8>>::new(vec![4, 5, 6]);
    
    assert!(!data1.ct_eq(&data2));
}

#[cfg(feature = "conversions")]
#[test]
fn dynamic_ct_eq_empty() {
    let empty1 = Dynamic::<Vec<u8>>::new(Vec::new());
    let empty2 = Dynamic::<Vec<u8>>::new(Vec::new());
    
    assert!(empty1.ct_eq(&empty2));
}

#[cfg(feature = "conversions")]
#[test]
fn dynamic_ct_eq_different_lengths() {
    let short = Dynamic::<Vec<u8>>::new(vec![1, 2]);
    let long = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    
    assert!(!short.ct_eq(&long));
    assert!(!long.ct_eq(&short));
}

#[cfg(feature = "conversions")]
#[test]
fn dynamic_ct_eq_one_byte_different() {
    let data1 = Dynamic::<Vec<u8>>::new(vec![42u8; 32]);
    let mut arr = vec![42u8; 32];
    arr[0] = 99;
    let data2 = Dynamic::<Vec<u8>>::new(arr);
    
    assert!(!data1.ct_eq(&data2));
}

#[cfg(feature = "conversions")]
#[test]
fn dynamic_ct_eq_string_vs_vec() {
    // These should not be comparable (different types)
    // But we test that ct_eq works for each type independently
    let str_val = Dynamic::<String>::new("hello".to_string());
    let str_val2 = Dynamic::<String>::new("hello".to_string());
    
    assert!(str_val.ct_eq(&str_val2));
}

// ──────────────────────────────────────────────────────────────
// generate_random() edge cases (feature-gated)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "rand")]
#[test]
fn dynamic_generate_random_different_sizes() {
    let data8 = Dynamic::<Vec<u8>>::generate_random(8);
    let data16 = Dynamic::<Vec<u8>>::generate_random(16);
    let data32 = Dynamic::<Vec<u8>>::generate_random(32);
    let data64 = Dynamic::<Vec<u8>>::generate_random(64);
    
    assert_eq!(data8.len(), 8);
    assert_eq!(data16.len(), 16);
    assert_eq!(data32.len(), 32);
    assert_eq!(data64.len(), 64);
    
    // Verify randomness (not all zeros)
    assert!(!data8.expose_secret().iter().all(|&b| b == 0));
    assert!(!data16.expose_secret().iter().all(|&b| b == 0));
    assert!(!data32.expose_secret().iter().all(|&b| b == 0));
    assert!(!data64.expose_secret().iter().all(|&b| b == 0));
}

#[cfg(feature = "rand")]
#[test]
fn dynamic_generate_random_empty() {
    let data = Dynamic::<Vec<u8>>::generate_random(0);
    assert_eq!(data.len(), 0);
    assert!(data.is_empty());
}

#[cfg(feature = "rand")]
#[test]
fn dynamic_generate_random_single_byte() {
    let data = Dynamic::<Vec<u8>>::generate_random(1);
    assert_eq!(data.len(), 1);
    assert!(*data.expose_secret() != [0u8]);
}

#[cfg(feature = "rand")]
#[test]
fn dynamic_generate_random_large() {
    let data = Dynamic::<Vec<u8>>::generate_random(4096);
    assert_eq!(data.len(), 4096);
    assert!(!data.expose_secret().iter().all(|&b| b == 0));
}

#[cfg(feature = "rand")]
#[test]
fn dynamic_generate_random_multiple_different() {
    // Generate many values and verify they're all different
    let mut values = Vec::new();
    for _ in 0..50 {
        let data = Dynamic::<Vec<u8>>::generate_random(32);
        values.push(data.expose_secret().to_vec());
    }
    
    // Check that all values are unique
    for i in 0..values.len() {
        for j in (i + 1)..values.len() {
            assert_ne!(values[i], values[j], "Duplicate random values found!");
        }
    }
}

#[cfg(feature = "rand")]
#[test]
fn dynamic_generate_random_not_all_zeros() {
    let mut all_zero = true;
    for _ in 0..100 {
        let data = Dynamic::<Vec<u8>>::generate_random(32);
        if !data.expose_secret().iter().all(|&b| b == 0) {
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
fn dynamic_zeroize_string() {
    use zeroize::Zeroize;
    
    let mut pw = Dynamic::<String>::new("secret".to_string());
    pw.zeroize();
    
    // After zeroize, String is cleared
    assert!(pw.is_empty());
    assert_eq!(pw.expose_secret(), "");
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_zeroize_vec() {
    use zeroize::Zeroize;
    
    let mut data = Dynamic::<Vec<u8>>::new(vec![42u8; 32]);
    let original_len = data.len();
    data.zeroize();
    
    // After zeroize, Vec is cleared
    assert!(data.is_empty());
    assert_eq!(data.len(), 0);
    assert_ne!(original_len, 0); // Verify it was non-empty before
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_zeroize_empty() {
    use zeroize::Zeroize;
    
    let mut empty_str = Dynamic::<String>::new("".to_string());
    let mut empty_vec = Dynamic::<Vec<u8>>::new(Vec::new());
    
    empty_str.zeroize();
    empty_vec.zeroize();
    
    // Should remain empty
    assert!(empty_str.is_empty());
    assert!(empty_vec.is_empty());
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_zeroize_large() {
    use zeroize::Zeroize;
    
    let mut large = Dynamic::<Vec<u8>>::new(vec![0xFFu8; 1024]);
    large.zeroize();
    
    // Should be cleared
    assert!(large.is_empty());
    assert_eq!(large.len(), 0);
}

// ──────────────────────────────────────────────────────────────
// no_clone() conversion edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_no_clone_string_preserves_data() {
    let dynamic = Dynamic::<String>::new("secret".to_string());
    let no_clone = dynamic.no_clone();
    
    assert_eq!(no_clone.expose_secret(), "secret");
    assert_eq!(no_clone.len(), 6);
}

#[test]
fn dynamic_no_clone_vec_preserves_data() {
    let dynamic = Dynamic::<Vec<u8>>::new(vec![1, 2, 3, 4]);
    let no_clone = dynamic.no_clone();
    
    assert_eq!(no_clone.expose_secret(), &[1, 2, 3, 4]);
    assert_eq!(no_clone.len(), 4);
}

#[test]
fn dynamic_no_clone_empty() {
    let empty_str = Dynamic::<String>::new("".to_string());
    let empty_vec = Dynamic::<Vec<u8>>::new(Vec::new());
    
    let no_clone_str = empty_str.no_clone();
    let no_clone_vec = empty_vec.no_clone();
    
    assert!(no_clone_str.is_empty());
    assert!(no_clone_vec.is_empty());
}

// ──────────────────────────────────────────────────────────────
// zeroize_now() explicit zeroization
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_zeroize_now_string() {
    let mut password = Dynamic::<String>::new("secret".to_string());
    assert_eq!(password.expose_secret(), "secret");
    
    password.zeroize_now();
    
    // After zeroize_now, String should be empty
    assert!(password.is_empty());
    assert_eq!(password.expose_secret(), "");
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_zeroize_now_vec() {
    let mut data = Dynamic::<Vec<u8>>::new(vec![42u8; 32]);
    assert_eq!(data.len(), 32);
    
    data.zeroize_now();
    
    // After zeroize_now, Vec should be empty
    assert!(data.is_empty());
    assert_eq!(data.len(), 0);
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_zeroize_now_empty() {
    let mut empty_str = Dynamic::<String>::new("".to_string());
    let mut empty_vec = Dynamic::<Vec<u8>>::new(Vec::new());
    
    empty_str.zeroize_now();
    empty_vec.zeroize_now();
    
    assert!(empty_str.is_empty());
    assert!(empty_vec.is_empty());
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_zeroize_now_large() {
    let mut large = Dynamic::<Vec<u8>>::new(vec![0xFFu8; 1024]);
    assert_eq!(large.len(), 1024);
    
    large.zeroize_now();
    
    assert!(large.is_empty());
    assert_eq!(large.len(), 0);
}

// ──────────────────────────────────────────────────────────────
// Real-world integration scenarios
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_workflow_string_creation_to_usage() {
    // Create from string literal
    let pw: Dynamic<String> = "hunter2".into();
    
    // Access and verify
    assert_eq!(pw.len(), 7);
    assert_eq!(pw.expose_secret(), "hunter2");
    
    // Mutate
    let mut pw_mut = pw.clone();
    pw_mut.expose_secret_mut().push('!');
    
    // Verify original unchanged
    assert_eq!(pw.expose_secret(), "hunter2");
    assert_eq!(pw_mut.expose_secret(), "hunter2!");
}

#[test]
fn dynamic_workflow_vec_creation_to_usage() {
    // Create from vec
    let data: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    
    // Access and verify
    assert_eq!(data.len(), 3);
    assert_eq!(data.expose_secret(), &[1, 2, 3]);
    
    // Mutate
    let mut data_mut = data.clone();
    data_mut.expose_secret_mut().push(4);
    
    // Verify original unchanged
    assert_eq!(data.expose_secret(), &[1, 2, 3]);
    assert_eq!(data_mut.expose_secret(), &[1, 2, 3, 4]);
}

#[test]
fn dynamic_workflow_from_box_to_no_clone() {
    // Create from Box
    let boxed = Box::new("secret".to_string());
    let dynamic: Dynamic<String> = boxed.into();
    
    // Convert to no_clone
    let no_clone = dynamic.no_clone();
    
    // Verify data preserved
    assert_eq!(no_clone.expose_secret(), "secret");
}

#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn dynamic_workflow_random_to_comparison() {
    // Generate random
    let data1 = Dynamic::<Vec<u8>>::generate_random(32);
    let data2 = Dynamic::<Vec<u8>>::generate_random(32);
    
    // Compare (should be different)
    assert!(!data1.ct_eq(&data2));
    
    // Clone and compare (should be same)
    let data1_clone = data1.clone();
    assert!(data1.ct_eq(&data1_clone));
}

// ──────────────────────────────────────────────────────────────
// Edge cases: String operations
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_string_push_operations() {
    let mut pw = Dynamic::<String>::new("hello".to_string());
    
    pw.expose_secret_mut().push(' ');
    assert_eq!(pw.expose_secret(), "hello ");
    
    pw.expose_secret_mut().push_str("world");
    assert_eq!(pw.expose_secret(), "hello world");
    
    pw.expose_secret_mut().pop();
    assert_eq!(pw.expose_secret(), "hello worl");
}

#[test]
fn dynamic_string_shrink_to_fit() {
    let mut pw = Dynamic::<String>::new("hello".to_string());
    pw.expose_secret_mut().push_str(" world");
    
    // Shrink to fit after mutation
    pw.expose_secret_mut().shrink_to_fit();
    assert_eq!(pw.expose_secret(), "hello world");
}

#[test]
fn dynamic_string_unicode_operations() {
    let mut pw = Dynamic::<String>::new("hello".to_string());
    pw.expose_secret_mut().push_str(" 世界");
    
    assert_eq!(pw.expose_secret(), "hello 世界");
    assert_eq!(pw.len(), 12); // UTF-8 byte length
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Vec operations
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_vec_push_pop() {
    let mut data = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    
    data.expose_secret_mut().push(4);
    assert_eq!(data.expose_secret(), &[1, 2, 3, 4]);
    
    let popped = data.expose_secret_mut().pop();
    assert_eq!(popped, Some(4));
    assert_eq!(data.expose_secret(), &[1, 2, 3]);
}

#[test]
fn dynamic_vec_extend() {
    let mut data = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    
    data.expose_secret_mut().extend_from_slice(&[4, 5, 6]);
    assert_eq!(data.expose_secret(), &[1, 2, 3, 4, 5, 6]);
    
    data.expose_secret_mut().clear();
    assert!(data.is_empty());
}

#[test]
fn dynamic_vec_insert_remove() {
    let mut data = Dynamic::<Vec<u8>>::new(vec![1, 3]);
    
    data.expose_secret_mut().insert(1, 2);
    assert_eq!(data.expose_secret(), &[1, 2, 3]);
    
    let removed = data.expose_secret_mut().remove(1);
    assert_eq!(removed, 2);
    assert_eq!(data.expose_secret(), &[1, 3]);
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Pattern filling
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_vec_pattern_fill() {
    let mut data = Dynamic::<Vec<u8>>::new(vec![0u8; 32]);
    
    // Fill with pattern
    for i in 0..32 {
        data.expose_secret_mut()[i] = (i % 256) as u8;
    }
    
    // Verify pattern
    for i in 0..32 {
        assert_eq!(data.expose_secret()[i], (i % 256) as u8);
    }
}

#[test]
fn dynamic_vec_all_zeros() {
    let data = Dynamic::<Vec<u8>>::new(vec![0u8; 32]);
    assert!(data.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn dynamic_vec_all_ones() {
    let data = Dynamic::<Vec<u8>>::new(vec![0xFFu8; 32]);
    assert!(data.expose_secret().iter().all(|&b| b == 0xFF));
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Maximum reasonable sizes
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_max_reasonable_size() {
    // Test with a reasonably large size
    let data = Dynamic::<Vec<u8>>::new(vec![42u8; 1024]);
    assert_eq!(data.len(), 1024);
    
    // Verify we can access all elements
    assert_eq!(data.expose_secret()[0], 42);
    assert_eq!(data.expose_secret()[1023], 42);
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Multiple types together
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_multiple_types_together() {
    let pw = Dynamic::<String>::new("hunter2".to_string());
    let data = Dynamic::<Vec<u8>>::new(vec![1, 2, 3]);
    let ints = Dynamic::<Vec<i32>>::new(vec![10, 20, 30]);
    
    // All should work independently
    assert_eq!(pw.len(), 7);
    assert_eq!(data.len(), 3);
    assert_eq!(ints.len(), 3);
    
    // All should require explicit access
    assert_eq!(pw.expose_secret(), "hunter2");
    assert_eq!(data.expose_secret(), &[1, 2, 3]);
    assert_eq!(ints.expose_secret(), &[10, 20, 30]);
}

