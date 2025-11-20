// tests/zeroize_tests.rs
// Updated for secure-gate 0.4.0 — uses SecureGate<T>

#[cfg(feature = "zeroize")]
mod tests {
    #[cfg(feature = "unsafe-wipe")]
    use std::collections::HashMap;
    #[cfg(feature = "unsafe-wipe")]
    use std::sync::{Arc, Mutex};
    #[cfg(feature = "unsafe-wipe")]
    use std::thread;
    #[cfg(feature = "unsafe-wipe")]
    use std::time::{Duration, Instant};

    use secure_gate::SecureGate;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    // --------------------------------------------------------------------- //
    // 1. Core zeroization invariants (Vec<u8> and String)
    // --------------------------------------------------------------------- //

    #[test]
    fn zeroize_preserves_length_and_capacity_vec() {
        let mut v = SecureGate::new(vec![99u8; 100]);
        let len = v.expose().len();
        let cap = v.expose().capacity();

        v.zeroize();

        assert_eq!(v.expose().len(), len, "zeroize must not change .len()");
        assert_eq!(
            v.expose().capacity(),
            cap,
            "zeroize must not change capacity"
        );
        assert!(
            v.expose().iter().all(|&b| b == 0),
            "all bytes must be zeroed"
        );
    }

    #[test]
    fn zeroize_regression_original_bug() {
        let mut v = SecureGate::new(vec![10u8]);
        v.expose_mut().push(0xAA);
        let pre_len = v.expose().len();

        v.zeroize();

        assert_eq!(v.expose().len(), pre_len, "zeroize must not clear/truncate");
        assert!(v.expose().iter().all(|&b| b == 0));
    }

    #[test]
    fn zeroize_preserves_length_and_capacity_string() {
        let mut s = SecureGate::new("hunter2".to_string());
        let len = s.expose().len();
        let cap = s.expose().capacity();

        s.zeroize();

        assert_eq!(s.expose().len(), len);
        assert_eq!(s.expose().capacity(), cap);
        assert_eq!(s.expose().as_str(), "\0".repeat(len));
    }

    // --------------------------------------------------------------------- //
    // 2. ZeroizeOnDrop works for custom types
    // --------------------------------------------------------------------- //

    #[test]
    fn zeroize_on_drop_works() {
        #[derive(Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
        struct Secret(Vec<u8>);

        let original = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let s = SecureGate::new(Secret(original.clone()));

        assert_eq!(s.expose().0, original);

        drop(s);
        // ZeroizeOnDrop called → memory wiped
        // Test passes if no panic and derive worked
    }

    // --------------------------------------------------------------------- //
    // 3. String-based secure wrapper works
    // --------------------------------------------------------------------- //

    #[test]
    fn secure_string_zeroize_works() {
        let mut pw = SecureGate::new("supersecret".to_string());

        assert_eq!(pw.expose().as_str(), "supersecret");

        pw.zeroize();

        let wiped = pw.expose().as_str();
        assert_eq!(wiped.len(), "supersecret".len());
        assert_eq!(wiped, "\0".repeat("supersecret".len()));
    }

    #[test]
    fn secure_string_finish_mut_shrink() {
        let mut pw = SecureGate::new(String::with_capacity(100));
        pw.expose_mut().push_str("short");
        let old_cap = pw.expose().capacity();

        pw.finish_mut();

        let new_cap = pw.expose().capacity();
        assert!(new_cap <= old_cap);
        assert!(new_cap >= pw.expose().len());
    }

    #[test]
    fn secure_string_clone_isolation() {
        let pw1 = SecureGate::new("original".to_string());
        let pw2 = pw1.clone();

        let mut pw1_mut = pw1.clone();
        pw1_mut.expose_mut().push_str("modified");

        assert_eq!(pw1.expose().as_str(), "original");
        assert_eq!(pw2.expose().as_str(), "original");
        assert_eq!(pw1_mut.expose().as_str(), "originalmodified");
    }

    // --------------------------------------------------------------------- //
    // 4. Edge/Breaking Tests for Unsafe-Wipe Path
    // --------------------------------------------------------------------- //

    #[cfg(feature = "unsafe-wipe")]
    #[test]
    fn unsafe_wipe_overallocated_preserves_slack_zeroed() {
        let mut s = SecureGate::new(String::with_capacity(1024));
        s.expose_mut().push_str("short");
        let original_len = s.expose().len();
        let original_cap = s.expose().capacity();

        s.zeroize();

        assert_eq!(s.expose().len(), original_len, "len must hold");
        assert_eq!(s.expose().capacity(), original_cap, "cap must hold");
        assert_eq!(
            s.expose().as_str(),
            "\0".repeat(original_len),
            "visible bytes zeroed"
        );

        let post_full: Vec<u8> = unsafe {
            let vec = s.expose_mut().as_mut_vec();
            let ptr = vec.as_ptr();
            std::slice::from_raw_parts(ptr, original_cap).to_vec()
        };
        assert!(
            post_full.iter().all(|&b| b == 0),
            "full buffer (incl. slack) must be zeroed—no residue"
        );
    }

    #[cfg(feature = "unsafe-wipe")]
    #[test]
    fn unsafe_wipe_concurrent_mut_completes() {
        let s = Arc::new(Mutex::new(SecureGate::new("concurrent".to_string())));
        let mut handles = vec![];

        for _ in 0..2 {
            let s_clone = Arc::clone(&s);
            handles.push(thread::spawn(move || {
                let mut guard = s_clone.lock().unwrap();
                let _len = guard.expose().len();
                guard.zeroize();
            }));
        }

        let start = Instant::now();
        for h in handles {
            h.join().expect("Thread join failed—potential deadlock");
        }
        let duration = start.elapsed();
        assert!(
            duration < Duration::from_secs(1),
            "Contention too high—possible lock flaw"
        );
    }

    #[cfg(feature = "unsafe-wipe")]
    #[test]
    fn unsafe_wipe_large_buffer_no_panic() {
        let payload = "a".repeat(1_000_000);
        let mut s = SecureGate::new(payload);
        let original_len = s.expose().len();
        let original_cap = s.expose().capacity();

        s.expose_mut().reserve(1_000_000);

        let start = Instant::now();
        s.zeroize();
        let duration = start.elapsed();

        assert_eq!(s.expose().len(), original_len, "len preserved");
        assert!(
            s.expose().capacity() >= original_cap + 1_000_000,
            "cap grew"
        );
        assert!(
            s.expose().as_bytes().iter().all(|&b| b == 0),
            "bytes zeroed"
        );
        assert!(duration < Duration::from_millis(100), "zeroize too slow");
    }

    #[cfg(feature = "unsafe-wipe")]
    #[test]
    fn unsafe_wipe_timing_variance_low() {
        let mut timings = HashMap::new();
        let sizes = [0, 10, 100, 1000, 10000];

        for &size in &sizes {
            let mut total = Duration::new(0, 0);
            let iterations = 1000;

            for _ in 0..iterations {
                let mut s = SecureGate::new("a".repeat(size));
                s.expose_mut().reserve(size * 2);

                let start = Instant::now();
                s.zeroize();
                total += start.elapsed();
            }

            let avg = total / iterations;
            timings.insert(size, avg);
        }

        let min_time = *timings.values().min().unwrap();
        let max_time = *timings.values().max().unwrap();
        let variance_ns = (max_time - min_time).as_nanos();
        assert!(
            variance_ns < 1_000_000u128,
            "Timing leak detected: variance {variance_ns}ns"
        );
        println!("Timings: {timings:?}");
    }

    #[cfg(feature = "unsafe-wipe")]
    #[test]
    fn unsafe_wipe_string_preserves_length_and_zeros_bytes() {
        let mut s = SecureGate::new("supersecret".to_string());

        let len = s.expose().len();
        let cap = s.expose().capacity();

        s.zeroize();

        assert_eq!(s.expose().len(), len, "unsafe-wipe must preserve length");
        assert_eq!(
            s.expose().capacity(),
            cap,
            "unsafe-wipe must preserve capacity"
        );
        assert_eq!(
            s.expose().as_str(),
            "\0".repeat(len),
            "all bytes must be zeroed"
        );
    }
}

// ------------------------------------------------------------------------- //
// Fallback mode (no zeroize) — basic sanity
// ------------------------------------------------------------------------- //

#[cfg(not(feature = "zeroize"))]
#[test]
fn fallback_secure_string_works() {
    use secure_gate::SecureGate;
    let mut pw = SecureGate::new("fallback".to_string());
    pw.expose_mut().push_str("!!!");
    assert_eq!(pw.expose().as_str(), "fallback!!!");
}
