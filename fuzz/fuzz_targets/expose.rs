// fuzz/fuzz_targets/expose.rs
// Updated for v0.8.0 — comprehensive API coverage including with_secret, Debug, conversions
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, Fixed, ExposeSecret, ExposeSecretMut};
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec, FuzzFixed32, FuzzFixed16};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = Unstructured::new(data);

    let fixed_32 = match FuzzFixed32::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };
    let fixed_16 = match FuzzFixed16::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };
    let dyn_vec = match FuzzDynamicVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };
    let dyn_str = match FuzzDynamicString::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    // 1. Growable Vec<u8>
    let mut vec_dyn: Dynamic<Vec<u8>> = Dynamic::new(dyn_vec.expose_secret().clone());
    vec_dyn.expose_secret_mut().reverse();
    vec_dyn.expose_secret_mut().truncate(data.len().min(64));
    vec_dyn.expose_secret_mut().extend_from_slice(b"fuzz");
    vec_dyn.expose_secret_mut().shrink_to_fit();

    // 2. Fixed-size array
    let mut fixed_key = fixed_32;
    fixed_key.expose_secret_mut()[0] = 0xFF;

    // 3. String handling
    let mut dyn_str_mut: Dynamic<String> = Dynamic::new(dyn_str.expose_secret().clone());
    dyn_str_mut.expose_secret_mut().push('!');

    // 4. Fixed-size nonce
    let _nonce_arr = fixed_key.expose_secret();
    let fixed_nonce = Fixed::new([0u8; 32]);
    let _ = fixed_nonce.expose_secret().len(); // ← fixed

    // 5. Clone — all access through expose_secret()
    let cloneable = Dynamic::<Vec<u8>>::new(vec![1u8, 2, 3]);

    let _default = Dynamic::<String>::new(String::new());

    // All access must go through expose_secret() — security model enforced
    let _inner_ref = cloneable.expose_secret();

    // 6. Shrink to fit helpers (using explicit exposure)
    {
        let mut v = Dynamic::<Vec<u8>>::new(vec![0u8; 1000]);
        v.expose_secret_mut().truncate(10);
        v.expose_secret_mut().shrink_to_fit();
    }
    {
        let mut s = Dynamic::<String>::new("long string with excess capacity".to_string());
        s.expose_secret_mut().push_str("!!!");
        s.expose_secret_mut().shrink_to_fit();
    }

    // 7. Borrowing stress — immutable
    {
        let view_imm1 = vec_dyn.expose_secret();
        let _ = view_imm1.len();

        if !data.is_empty() && data[0] % 2 == 0 {
            let view_imm2 = vec_dyn.expose_secret();
            let _ = view_imm2.as_slice()[0];
            let nested_ref: &[u8] = &**view_imm2;
            let _ = nested_ref.len();
        }
    }

    // 8. Borrowing stress — mutable
    {
        let view_mut = fixed_key.expose_secret_mut();
        view_mut[1] = 0x42;

        let str_imm = dyn_str_mut.expose_secret();
        let _ = str_imm.as_str();

        let str_mut = dyn_str_mut.expose_secret_mut();
        str_mut.push('?');
        let nested_mut: &mut String = &mut *str_mut;
        nested_mut.push('@');
    }

    // 9. Scoped drop stress
    {
        let temp_dyn = Dynamic::<Vec<u8>>::new(vec![0u8; 10]);
        let temp_view = temp_dyn.expose_secret();
        let _ = temp_view.len();
        drop(temp_dyn);
    }

    // 10. with_secret / with_secret_mut scoped closure coverage (recommended API)
    {
        // Test with_secret on all types (fixed_32 was moved into fixed_key, use that)
        let _sum = fixed_key.with_secret(|arr| arr.iter().sum::<u8>());
        let _len = dyn_vec.with_secret(|v| v.len());
        let _str_len = dyn_str.with_secret(|s| s.len());

        // Test with_secret_mut on mutable operations
        vec_dyn.with_secret_mut(|v| {
            v.reverse();
            v.truncate(10);
        });
        fixed_key.with_secret_mut(|arr| arr[0] = 0x42);
        dyn_str_mut.with_secret_mut(|s| s.push_str("_scoped"));
    }

    // 11. Debug REDACTED verification (fixed_32 moved into fixed_key, use that)
    {
        let debug_output = format!("{:?}", fixed_key);
        assert!(debug_output.contains("[REDACTED]"), "Debug should contain REDACTED");
        assert!(!debug_output.contains(&format!("{:x}", fixed_key.expose_secret()[0])), "Debug should not leak bytes");

        let debug_dyn = format!("{:?}", dyn_vec);
        assert!(debug_dyn.contains("[REDACTED]"), "Dynamic Debug should contain REDACTED");
    }

    // 12. From/TryFrom conversions
    {
        // Fixed from [u8; N]
        let arr = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let fixed_from_arr = Fixed::from(arr);
        assert_eq!(fixed_from_arr.expose_secret(), &arr);

        // Fixed try_from &[u8] (exact size succeeds)
        let slice: &[u8] = &[42u8; 16];
        if let Ok(fixed_from_slice) = Fixed::<[u8; 16]>::try_from(slice) {
            assert_eq!(fixed_from_slice.expose_secret(), &[42u8; 16]);
        }

        // Dynamic from &[u8] and &str
        let dyn_from_slice = Dynamic::<Vec<u8>>::from(&[1, 2, 3][..]);
        assert_eq!(dyn_from_slice.expose_secret(), &[1, 2, 3]);

        let dyn_from_str = Dynamic::<String>::from("test");
        assert_eq!(dyn_from_str.expose_secret(), "test");

        // Dynamic from owned types
        let owned_vec = vec![4, 5, 6];
        let dyn_from_vec = Dynamic::from(owned_vec.clone());
        assert_eq!(dyn_from_vec.expose_secret(), &owned_vec);
    }

    // 13. from_random smoke test
    #[cfg(feature = "rand")]
    {
        let _random_fixed = Fixed::<[u8; 32]>::from_random();
        let _random_dyn = Dynamic::<Vec<u8>>::from_random(16);
        // Just verify they don't panic, don't check randomness
    }

    // 14. Clone round-trip — requires CloneableSecret marker on the inner type.
    // CloneableSecret is an explicit opt-in that can't be impl'd for foreign types
    // (Vec<u8>, [u8; N]) in this crate due to orphan rules. We test via a local type.
    #[cfg(feature = "cloneable")]
    {
        use secure_gate::CloneableSecret;
        use zeroize::Zeroize;

        // Local wrapper that opts into cloning
        #[derive(Clone, Zeroize)]
        struct CloneKey(Vec<u8>);
        impl CloneableSecret for CloneKey {}

        // Verify the marker impl compiles and CloneKey is Clone
        let original = CloneKey(data.to_vec());
        let _cloned = original.clone();
        drop(original);
    }

    // 15. len() / is_empty() consistency (use fixed_key since fixed_32 was moved)
    {
        assert_eq!(fixed_key.len(), 32);
        assert!(!fixed_key.is_empty());

        assert_eq!(fixed_16.len(), 16);
        assert!(!fixed_16.is_empty());

        let dyn_len = dyn_vec.len();
        assert_eq!(dyn_len, dyn_vec.expose_secret().len());
        assert_eq!(dyn_vec.is_empty(), dyn_len == 0);

        let str_len = dyn_str.len();
        assert_eq!(str_len, dyn_str.expose_secret().len());
        assert_eq!(dyn_str.is_empty(), str_len == 0);
    }
});
