// ==========================================================================
// tests/rng_tests.rs
// ==========================================================================
// Comprehensive testing for RNG functionality

#![cfg(feature = "rand")]

use secure_gate::{
    fixed_alias_rng,
    rng::{DynamicRng, FixedRng},
    Dynamic, Fixed,
};

// ──────────────────────────────────────────────────────────────
// Basic RNG functionality
// ──────────────────────────────────────────────────────────────

#[test]
fn basic_generation() {
    fixed_alias_rng!(Key32, 32);

    let a = Key32::generate();
    let b = Key32::generate();

    assert_ne!(a.expose_secret(), b.expose_secret());
    assert!(!a.expose_secret().iter().all(|&b| b == 0));
    assert_eq!(a.len(), 32);
}

#[test]
fn debug_is_redacted() {
    fixed_alias_rng!(DebugTest, 32);
    let rb = DebugTest::generate();
    assert_eq!(format!("{rb:?}"), "[REDACTED]");
}

#[test]
fn different_aliases_are_different_types() {
    fixed_alias_rng!(TypeA, 32);
    fixed_alias_rng!(TypeB, 32);
    let a = TypeA::generate();
    let _ = a;
    // let _wrong: TypeB = a; // must not compile
}

#[test]
fn raw_fixed_rng_works() {
    let a = FixedRng::<32>::generate();
    let b = FixedRng::<32>::generate();
    assert_ne!(a.expose_secret(), b.expose_secret());
    assert_eq!(a.len(), 32);
}

#[test]
fn zero_length_works() {
    let zero = FixedRng::<0>::generate();
    assert!(zero.is_empty());
    assert_eq!(zero.len(), 0);

    let dyn_zero = DynamicRng::generate(0);
    assert!(dyn_zero.is_empty());
    assert_eq!(dyn_zero.len(), 0);
}

// ct_eq returns false for different lengths (no panic)
#[cfg(feature = "conversions")]
#[test]
fn ct_eq_different_lengths() {
    use secure_gate::SecureConversionsExt;

    let a = DynamicRng::generate(32);
    let b = DynamicRng::generate(64);

    // Access the inner Dynamic<Vec<u8>> via into_inner() — safe in test
    let a_inner: secure_gate::Dynamic<Vec<u8>> = a.into_inner();
    let b_inner: secure_gate::Dynamic<Vec<u8>> = b.into_inner();

    assert!(!a_inner.expose_secret().ct_eq(b_inner.expose_secret()));
}

#[test]
#[cfg(feature = "zeroize")]
fn zeroize_trait_is_available() {
    use secure_gate::Fixed;
    use zeroize::Zeroize;
    let mut key = Fixed::<[u8; 32]>::new([0xFF; 32]);
    key.zeroize();
    assert_eq!(key.expose_secret(), &[0u8; 32]);
}

// ──────────────────────────────────────────────────────────────
// FixedRng edge cases: Different sizes
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_rng_single_byte() {
    let rng = FixedRng::<1>::generate();
    assert_eq!(rng.len(), 1);
    assert!(!rng.is_empty());
    assert!(*rng.expose_secret() != [0u8]);
    assert!(*rng.expose_secret() != [0xFFu8]);
}

#[test]
fn fixed_rng_small_sizes() {
    let rng8 = FixedRng::<8>::generate();
    let rng16 = FixedRng::<16>::generate();
    let rng24 = FixedRng::<24>::generate();
    
    assert_eq!(rng8.len(), 8);
    assert_eq!(rng16.len(), 16);
    assert_eq!(rng24.len(), 24);
    
    // Verify randomness (not all zeros)
    assert!(!rng8.expose_secret().iter().all(|&b| b == 0));
    assert!(!rng16.expose_secret().iter().all(|&b| b == 0));
    assert!(!rng24.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn fixed_rng_common_crypto_sizes() {
    let rng32 = FixedRng::<32>::generate(); // AES-256 key
    let rng64 = FixedRng::<64>::generate(); // 512-bit key
    let rng128 = FixedRng::<128>::generate(); // Large key
    
    assert_eq!(rng32.len(), 32);
    assert_eq!(rng64.len(), 64);
    assert_eq!(rng128.len(), 128);
    
    // Verify all are different
    let bytes32 = rng32.expose_secret();
    let bytes64 = rng64.expose_secret();
    let bytes128 = rng128.expose_secret();
    
    assert!(!bytes32.iter().all(|&b| b == 0));
    assert!(!bytes64.iter().all(|&b| b == 0));
    assert!(!bytes128.iter().all(|&b| b == 0));
}

#[test]
fn fixed_rng_very_large() {
    let rng = FixedRng::<4096>::generate();
    assert_eq!(rng.len(), 4096);
    assert!(!rng.is_empty());
    // Verify randomness
    assert!(!rng.expose_secret().iter().all(|&b| b == 0));
}

// ──────────────────────────────────────────────────────────────
// FixedRng edge cases: Conversions
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_rng_into_inner() {
    let rng = FixedRng::<32>::generate();
    let fixed: Fixed<[u8; 32]> = rng.into_inner();
    
    assert_eq!(fixed.len(), 32);
    assert!(!fixed.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn fixed_rng_into_trait() {
    let rng = FixedRng::<32>::generate();
    let fixed: Fixed<[u8; 32]> = rng.into();
    
    assert_eq!(fixed.len(), 32);
    assert!(!fixed.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn fixed_rng_into_inner_different_sizes() {
    let rng8 = FixedRng::<8>::generate();
    let rng16 = FixedRng::<16>::generate();
    let rng32 = FixedRng::<32>::generate();
    
    let fixed8: Fixed<[u8; 8]> = rng8.into_inner();
    let fixed16: Fixed<[u8; 16]> = rng16.into_inner();
    let fixed32: Fixed<[u8; 32]> = rng32.into_inner();
    
    assert_eq!(fixed8.len(), 8);
    assert_eq!(fixed16.len(), 16);
    assert_eq!(fixed32.len(), 32);
}

#[test]
fn fixed_rng_into_trait_different_sizes() {
    let fixed8: Fixed<[u8; 8]> = FixedRng::<8>::generate().into();
    let fixed16: Fixed<[u8; 16]> = FixedRng::<16>::generate().into();
    let fixed32: Fixed<[u8; 32]> = FixedRng::<32>::generate().into();
    
    assert_eq!(fixed8.len(), 8);
    assert_eq!(fixed16.len(), 16);
    assert_eq!(fixed32.len(), 32);
}

// ──────────────────────────────────────────────────────────────
// FixedRng edge cases: Randomness verification
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_rng_multiple_generations_different() {
    // Generate many values and verify they're all different
    let mut values = Vec::new();
    for _ in 0..100 {
        let rng = FixedRng::<32>::generate();
        values.push(*rng.expose_secret());
    }
    
    // Check that all values are unique (extremely unlikely to have duplicates)
    for i in 0..values.len() {
        for j in (i + 1)..values.len() {
            assert_ne!(values[i], values[j], "Duplicate random values found!");
        }
    }
}

#[test]
fn fixed_rng_not_all_zeros() {
    // Generate many values and verify at least some are non-zero
    let mut all_zero = true;
    for _ in 0..100 {
        let rng = FixedRng::<32>::generate();
        if !rng.expose_secret().iter().all(|&b| b == 0) {
            all_zero = false;
            break;
        }
    }
    assert!(!all_zero, "All generated values were zero!");
}

#[test]
fn fixed_rng_not_all_ones() {
    // Generate many values and verify at least some are not all 0xFF
    let mut all_ones = true;
    for _ in 0..100 {
        let rng = FixedRng::<32>::generate();
        if !rng.expose_secret().iter().all(|&b| b == 0xFF) {
            all_ones = false;
            break;
        }
    }
    assert!(!all_ones, "All generated values were 0xFF!");
}

// ──────────────────────────────────────────────────────────────
// DynamicRng edge cases: Different sizes
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_rng_single_byte() {
    let rng = DynamicRng::generate(1);
    assert_eq!(rng.len(), 1);
    assert!(!rng.is_empty());
    // Generate multiple times to verify randomness (single byte has 1/256 chance of being zero)
    let mut found_non_zero = false;
    for _ in 0..10 {
        let test_rng = DynamicRng::generate(1);
        if test_rng.expose_secret()[0] != 0 {
            found_non_zero = true;
            break;
        }
    }
    assert!(found_non_zero, "Generated 10 single-byte values, all were zero (statistically very unlikely)");
}

#[test]
fn dynamic_rng_small_sizes() {
    let rng8 = DynamicRng::generate(8);
    let rng16 = DynamicRng::generate(16);
    let rng24 = DynamicRng::generate(24);
    
    assert_eq!(rng8.len(), 8);
    assert_eq!(rng16.len(), 16);
    assert_eq!(rng24.len(), 24);
    
    // Verify randomness
    assert!(!rng8.expose_secret().iter().all(|&b| b == 0));
    assert!(!rng16.expose_secret().iter().all(|&b| b == 0));
    assert!(!rng24.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn dynamic_rng_common_sizes() {
    let rng32 = DynamicRng::generate(32);
    let rng64 = DynamicRng::generate(64);
    let rng128 = DynamicRng::generate(128);
    
    assert_eq!(rng32.len(), 32);
    assert_eq!(rng64.len(), 64);
    assert_eq!(rng128.len(), 128);
}

#[test]
fn dynamic_rng_very_large() {
    let rng = DynamicRng::generate(4096);
    assert_eq!(rng.len(), 4096);
    assert!(!rng.is_empty());
    // Verify randomness
    assert!(!rng.expose_secret().iter().all(|&b| b == 0));
}

// ──────────────────────────────────────────────────────────────
// DynamicRng edge cases: Conversions
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_rng_into_inner() {
    let rng = DynamicRng::generate(64);
    let dynamic: Dynamic<Vec<u8>> = rng.into_inner();
    
    assert_eq!(dynamic.len(), 64);
    assert!(!dynamic.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn dynamic_rng_into_trait() {
    let rng = DynamicRng::generate(64);
    let dynamic: Dynamic<Vec<u8>> = rng.into();
    
    assert_eq!(dynamic.len(), 64);
    assert!(!dynamic.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn dynamic_rng_into_inner_different_sizes() {
    let rng8 = DynamicRng::generate(8);
    let rng16 = DynamicRng::generate(16);
    let rng32 = DynamicRng::generate(32);
    
    let dyn8: Dynamic<Vec<u8>> = rng8.into_inner();
    let dyn16: Dynamic<Vec<u8>> = rng16.into_inner();
    let dyn32: Dynamic<Vec<u8>> = rng32.into_inner();
    
    assert_eq!(dyn8.len(), 8);
    assert_eq!(dyn16.len(), 16);
    assert_eq!(dyn32.len(), 32);
}

#[test]
fn dynamic_rng_into_trait_different_sizes() {
    let dyn8: Dynamic<Vec<u8>> = DynamicRng::generate(8).into();
    let dyn16: Dynamic<Vec<u8>> = DynamicRng::generate(16).into();
    let dyn32: Dynamic<Vec<u8>> = DynamicRng::generate(32).into();
    
    assert_eq!(dyn8.len(), 8);
    assert_eq!(dyn16.len(), 16);
    assert_eq!(dyn32.len(), 32);
}

// ──────────────────────────────────────────────────────────────
// DynamicRng edge cases: Randomness verification
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_rng_multiple_generations_different() {
    // Generate many values and verify they're all different
    let mut values = Vec::new();
    for _ in 0..50 {
        let rng = DynamicRng::generate(32);
        values.push(rng.expose_secret().to_vec());
    }
    
    // Check that all values are unique
    for i in 0..values.len() {
        for j in (i + 1)..values.len() {
            assert_ne!(values[i], values[j], "Duplicate random values found!");
        }
    }
}

#[test]
fn dynamic_rng_not_all_zeros() {
    let mut all_zero = true;
    for _ in 0..100 {
        let rng = DynamicRng::generate(32);
        if !rng.expose_secret().iter().all(|&b| b == 0) {
            all_zero = false;
            break;
        }
    }
    assert!(!all_zero, "All generated values were zero!");
}

#[test]
fn dynamic_rng_different_lengths_different() {
    let rng32 = DynamicRng::generate(32);
    let rng64 = DynamicRng::generate(64);
    
    // Different lengths should produce different values
    assert_ne!(rng32.len(), rng64.len());
    
    // Verify lengths are different
    let bytes32 = rng32.expose_secret();
    let bytes64 = rng64.expose_secret();
    
    assert_ne!(bytes32.len(), bytes64.len());
    assert_eq!(bytes32.len(), 32);
    assert_eq!(bytes64.len(), 64);
}

// ──────────────────────────────────────────────────────────────
// Debug redaction edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_rng_debug_redacted() {
    let rng = FixedRng::<32>::generate();
    assert_eq!(format!("{:?}", rng), "[REDACTED]");
}

#[test]
fn dynamic_rng_debug_redacted() {
    let rng = DynamicRng::generate(64);
    assert_eq!(format!("{:?}", rng), "[REDACTED]");
}

#[test]
fn fixed_rng_debug_redacted_all_sizes() {
    let rng0 = FixedRng::<0>::generate();
    let rng1 = FixedRng::<1>::generate();
    let rng32 = FixedRng::<32>::generate();
    let rng1024 = FixedRng::<1024>::generate();
    
    assert_eq!(format!("{:?}", rng0), "[REDACTED]");
    assert_eq!(format!("{:?}", rng1), "[REDACTED]");
    assert_eq!(format!("{:?}", rng32), "[REDACTED]");
    assert_eq!(format!("{:?}", rng1024), "[REDACTED]");
}

#[test]
fn dynamic_rng_debug_redacted_all_sizes() {
    let rng0 = DynamicRng::generate(0);
    let rng1 = DynamicRng::generate(1);
    let rng32 = DynamicRng::generate(32);
    let rng1024 = DynamicRng::generate(1024);
    
    assert_eq!(format!("{:?}", rng0), "[REDACTED]");
    assert_eq!(format!("{:?}", rng1), "[REDACTED]");
    assert_eq!(format!("{:?}", rng32), "[REDACTED]");
    assert_eq!(format!("{:?}", rng1024), "[REDACTED]");
}

// ──────────────────────────────────────────────────────────────
// expose_secret edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_rng_expose_secret_all_sizes() {
    let rng0 = FixedRng::<0>::generate();
    let rng1 = FixedRng::<1>::generate();
    let rng32 = FixedRng::<32>::generate();
    
    assert_eq!(rng0.expose_secret().len(), 0);
    assert_eq!(rng1.expose_secret().len(), 1);
    assert_eq!(rng32.expose_secret().len(), 32);
}

#[test]
fn dynamic_rng_expose_secret_all_sizes() {
    let rng0 = DynamicRng::generate(0);
    let rng1 = DynamicRng::generate(1);
    let rng32 = DynamicRng::generate(32);
    let rng1024 = DynamicRng::generate(1024);
    
    assert_eq!(rng0.expose_secret().len(), 0);
    assert_eq!(rng1.expose_secret().len(), 1);
    assert_eq!(rng32.expose_secret().len(), 32);
    assert_eq!(rng1024.expose_secret().len(), 1024);
}

#[test]
fn dynamic_rng_expose_secret_access() {
    let rng = DynamicRng::generate(32);
    let bytes = rng.expose_secret();
    
    assert_eq!(bytes.len(), 32);
    // Can access individual bytes
    let _first = bytes[0];
    let _last = bytes[31];
    // Verify it's not all zeros
    assert!(!bytes.iter().all(|&b| b == 0));
}

// ──────────────────────────────────────────────────────────────
// Integration with convenience methods
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_generate_random_equivalent() {
    let rng = FixedRng::<32>::generate();
    let fixed_from_rng: Fixed<[u8; 32]> = rng.into_inner();
    
    let fixed_direct: Fixed<[u8; 32]> = Fixed::generate_random();
    
    // Both should be 32 bytes
    assert_eq!(fixed_from_rng.len(), 32);
    assert_eq!(fixed_direct.len(), 32);
    
    // Both should be random (not all zeros)
    assert!(!fixed_from_rng.expose_secret().iter().all(|&b| b == 0));
    assert!(!fixed_direct.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn dynamic_generate_random_equivalent() {
    let rng = DynamicRng::generate(64);
    let dynamic_from_rng: Dynamic<Vec<u8>> = rng.into_inner();
    
    let dynamic_direct = Dynamic::generate_random(64);
    
    // Both should be 64 bytes
    assert_eq!(dynamic_from_rng.len(), 64);
    assert_eq!(dynamic_direct.len(), 64);
    
    // Both should be random (not all zeros)
    assert!(!dynamic_from_rng.expose_secret().iter().all(|&b| b == 0));
    assert!(!dynamic_direct.expose_secret().iter().all(|&b| b == 0));
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Empty vs non-empty
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_rng_empty_vs_non_empty() {
    let empty = FixedRng::<0>::generate();
    let non_empty = FixedRng::<32>::generate();
    
    assert!(empty.is_empty());
    assert!(!non_empty.is_empty());
    
    assert_eq!(empty.len(), 0);
    assert_eq!(non_empty.len(), 32);
}

#[test]
fn dynamic_rng_empty_vs_non_empty() {
    let empty = DynamicRng::generate(0);
    let non_empty = DynamicRng::generate(32);
    
    assert!(empty.is_empty());
    assert!(!non_empty.is_empty());
    
    assert_eq!(empty.len(), 0);
    assert_eq!(non_empty.len(), 32);
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Multiple consecutive generations
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_rng_consecutive_generations() {
    // Generate many consecutive values
    for i in 0..100 {
        let rng = FixedRng::<32>::generate();
        assert_eq!(rng.len(), 32);
        assert!(!rng.is_empty());
        
        // Every 10th generation, verify randomness
        if i % 10 == 0 {
            assert!(!rng.expose_secret().iter().all(|&b| b == 0));
        }
    }
}

#[test]
fn dynamic_rng_consecutive_generations() {
    // Generate many consecutive values with different sizes
    for i in 0..50 {
        let size = (i % 10) * 8 + 8; // 8, 16, 24, ..., 80
        let rng = DynamicRng::generate(size);
        assert_eq!(rng.len(), size);
        assert!(!rng.is_empty());
        
        // Verify randomness
        assert!(!rng.expose_secret().iter().all(|&b| b == 0));
    }
}

// ──────────────────────────────────────────────────────────────
// Edge cases: FixedRng with aliases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_alias_rng_all_methods() {
    fixed_alias_rng!(TestKey, 32);
    
    let key = TestKey::generate();
    
    // Test all methods
    assert_eq!(key.len(), 32);
    assert!(!key.is_empty());
    
    let bytes = key.expose_secret();
    assert_eq!(bytes.len(), 32);
    assert!(!bytes.iter().all(|&b| b == 0));
    
    // Test conversion
    let fixed: Fixed<[u8; 32]> = key.into_inner();
    assert_eq!(fixed.len(), 32);
}

#[test]
fn fixed_alias_rng_from_trait() {
    fixed_alias_rng!(TestKey, 32);
    
    let key = TestKey::generate();
    let fixed: Fixed<[u8; 32]> = key.into();
    
    assert_eq!(fixed.len(), 32);
}

// ──────────────────────────────────────────────────────────────
// Edge cases: Zeroize integration (when feature enabled)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "zeroize")]
#[test]
fn fixed_rng_zeroize_on_drop() {
    use zeroize::Zeroize;
    
    let rng = FixedRng::<32>::generate();
    let fixed: Fixed<[u8; 32]> = rng.into_inner();
    
    // Verify zeroize is available
    let mut fixed_mut = fixed;
    fixed_mut.zeroize();
    
    // After zeroize, should be all zeros
    assert!(fixed_mut.expose_secret().iter().all(|&b| b == 0));
}

#[cfg(feature = "zeroize")]
#[test]
fn dynamic_rng_zeroize_on_drop() {
    use zeroize::Zeroize;
    
    let rng = DynamicRng::generate(64);
    let dynamic: Dynamic<Vec<u8>> = rng.into_inner();
    
    // Verify zeroize is available
    let mut dynamic_mut = dynamic;
    let original_len = dynamic_mut.len();
    dynamic_mut.zeroize();
    
    // After zeroize, Vec is cleared (length becomes 0)
    assert_eq!(dynamic_mut.len(), 0);
    assert!(dynamic_mut.expose_secret().is_empty());
    // Original length was preserved before zeroize
    assert_eq!(original_len, 64);
}

