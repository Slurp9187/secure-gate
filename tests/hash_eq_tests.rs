// ==========================================================================
// tests/hash_eq_tests.rs
// ==========================================================================
// Tests for hash-based equality (Blake3) for large/variable secrets

#[cfg(test)]
mod tests {

    #[cfg(feature = "hash-eq")]
    use secure_gate::{Dynamic, Fixed, HashEq};

    #[cfg(feature = "hash-eq")]
    #[test]
    fn fixed_hash_eq_basic() {
        // Equal arrays
        let fixed1: Fixed<[u8; 4]> = Fixed::from([1u8, 2, 3, 4]);
        let fixed2: Fixed<[u8; 4]> = Fixed::from([1u8, 2, 3, 4]);
        assert!(fixed1.hash_eq(&fixed2));

        // Unequal arrays
        let fixed3: Fixed<[u8; 4]> = Fixed::from([1u8, 2, 3, 5]);
        assert!(!fixed1.hash_eq(&fixed3));
    }

    #[cfg(feature = "hash-eq")]
    #[test]
    fn dynamic_vec_hash_eq_basic() {
        // Equal vectors
        let dyn1: Dynamic<Vec<u8>> = vec![1u8, 2, 3, 4].into();
        let dyn2: Dynamic<Vec<u8>> = vec![1u8, 2, 3, 4].into();
        assert!(dyn1.hash_eq(&dyn2));

        // Unequal vectors (same length)
        let dyn3: Dynamic<Vec<u8>> = vec![1u8, 2, 3, 5].into();
        assert!(!dyn1.hash_eq(&dyn3));

        // Unequal vectors (different length)
        let dyn4: Dynamic<Vec<u8>> = vec![1u8, 2, 3].into();
        assert!(!dyn1.hash_eq(&dyn4));
    }

    #[cfg(feature = "hash-eq")]
    #[test]
    fn dynamic_string_hash_eq_basic() {
        // Equal strings
        let str1: Dynamic<String> = "hello".into();
        let str2: Dynamic<String> = "hello".into();
        assert!(str1.hash_eq(&str2));

        // Unequal strings
        let str3: Dynamic<String> = "world".into();
        assert!(!str1.hash_eq(&str3));

        // Different lengths
        let str4: Dynamic<String> = "hi".into();
        assert!(!str1.hash_eq(&str4));
    }

    #[cfg(feature = "hash-eq")]
    #[test]
    fn large_vectors_equality() {
        // Test with large vectors (>256 bytes)
        let data1 = vec![42u8; 1000];
        let data2 = vec![42u8; 1000];
        let data3 = vec![43u8; 1000];

        let dyn1: Dynamic<Vec<u8>> = data1.into();
        let dyn2: Dynamic<Vec<u8>> = data2.into();
        let dyn3: Dynamic<Vec<u8>> = data3.into();

        assert!(dyn1.hash_eq(&dyn2));
        assert!(!dyn1.hash_eq(&dyn3));
    }

    #[cfg(feature = "hash-eq")]
    #[test]
    fn collision_resistance_approximation() {
        // Blake3 has negligible collision probability; test with known different data
        // This is not exhaustive but ensures basic functionality
        let data1 = b"unique_data_123";
        let data2 = b"unique_data_456"; // Different data
        let data3 = b"unique_data_123"; // Same as data1

        let dyn1: Dynamic<Vec<u8>> = data1.to_vec().into();
        let dyn2: Dynamic<Vec<u8>> = data2.to_vec().into();
        let dyn3: Dynamic<Vec<u8>> = data3.to_vec().into();

        assert!(dyn1.hash_eq(&dyn3));
        assert!(!dyn1.hash_eq(&dyn2));
    }

    #[cfg(feature = "hash-eq")]
    #[test]
    fn timing_neutrality_approximation() {
        // Approximate timing test: run comparisons in a loop and ensure no obvious leaks
        // This is not precise but provides some assurance
        use std::time::Instant;

        let data1 = vec![0u8; 1000];
        let data2 = vec![0u8; 1000]; // Same
        let data3 = vec![1u8; 1000]; // Different at start

        let dyn1: Dynamic<Vec<u8>> = data1.into();
        let dyn2: Dynamic<Vec<u8>> = data2.into();
        let dyn3: Dynamic<Vec<u8>> = data3.into();

        let iterations = 1000;

        let start_equal = Instant::now();
        for _ in 0..iterations {
            let _ = dyn1.hash_eq(&dyn2);
        }
        let time_equal = start_equal.elapsed();

        let start_unequal = Instant::now();
        for _ in 0..iterations {
            let _ = dyn1.hash_eq(&dyn3);
        }
        let time_unequal = start_unequal.elapsed();

        // Times should be similar (within 30% tolerance for approximation)
        let ratio = time_equal.as_nanos() as f64 / time_unequal.as_nanos() as f64;
        assert!(
            ratio > 0.7 && ratio < 1.3,
            "Timing difference detected: equal={}ns, unequal={}ns",
            time_equal.as_nanos(),
            time_unequal.as_nanos()
        );
    }
}
