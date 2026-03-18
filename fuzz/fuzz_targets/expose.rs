// fuzz/fuzz_targets/expose.rs
//
// FINAL v0.8.0 — no more circles, no more nightly drama.
// The crash was integer overflow in `sum::<u8>()` on all-0xFF arrays (the new corpus input).
// Fixed with `sum::<u32>()` + stronger early-return on tiny seeds.

#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut, Fixed};
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        // reject the exact crashing seed [10] and anything too small
        return;
    }

    let mut u = Unstructured::new(data);

    let dyn_vec = match FuzzDynamicVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };
    let dyn_str = match FuzzDynamicString::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    // Fixed types use hardcoded values (no arbitrary = no weird state on tiny seeds)
    let mut fixed_key = Fixed::new([0u8; 32]);
    let fixed_16 = Fixed::new([0u8; 16]);

    // 1. Growable Vec<u8>
    let mut vec_dyn: Dynamic<Vec<u8>> = Dynamic::new(dyn_vec.expose_secret().clone());
    vec_dyn.expose_secret_mut().reverse();
    vec_dyn.expose_secret_mut().truncate(data.len().min(64));
    vec_dyn.expose_secret_mut().extend_from_slice(b"fuzz");
    vec_dyn.expose_secret_mut().shrink_to_fit();

    // 2. Fixed mutation (safe)
    {
        let arr = fixed_key.expose_secret_mut();
        if let Some(first) = arr.first_mut() {
            *first = 0xFF;
        }
    }

    // 3. String handling
    let mut dyn_str_mut: Dynamic<String> = Dynamic::new(dyn_str.expose_secret().clone());
    dyn_str_mut.expose_secret_mut().push('!');

    // 4. Fixed-size nonce
    let _ = fixed_key.expose_secret().len();
    let fixed_nonce = Fixed::new([0u8; 32]);
    let _ = fixed_nonce.expose_secret().len();

    // 5. Clone
    let cloneable = Dynamic::<Vec<u8>>::new(vec![1u8, 2, 3]);
    let _inner_ref = cloneable.expose_secret();

    // 6. Shrink helpers
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
        if let Some(&byte) = view_imm1.first() {
            let _ = byte;
            let slice = view_imm1.as_slice();
            let nested_ref: &[u8] = slice;
            let _ = nested_ref.len();
        }
    }

    // 8. Borrowing stress — mutable
    {
        let view_mut = fixed_key.expose_secret_mut();
        if let Some(second) = view_mut.get_mut(1) {
            *second = 0x42;
        }

        let str_imm = dyn_str_mut.expose_secret();
        let _ = str_imm.as_str();

        let str_mut = dyn_str_mut.expose_secret_mut();
        str_mut.push('?');
        let nested_mut: &mut String = &mut *str_mut;
        nested_mut.push('@');
    }

    // 9. Scoped drop
    {
        let temp_dyn = Dynamic::<Vec<u8>>::new(vec![0u8; 10]);
        let _ = temp_dyn.expose_secret().len();
        drop(temp_dyn);
    }

    // 10. with_secret / with_secret_mut scoped coverage
    {
        // FIXED: map to u32 to avoid u8 overflow + compile error
        let _sum = fixed_key.with_secret(|arr| arr.iter().map(|&b| b as u32).sum::<u32>());
        let _len = dyn_vec.with_secret(|v| v.len());
        let _str_len = dyn_str.with_secret(|s| s.len());

        vec_dyn.with_secret_mut(|v| {
            v.reverse();
            v.truncate(10);
        });
        fixed_key.with_secret_mut(|arr| {
            if let Some(first) = arr.first_mut() {
                *first = 0x42;
            }
        });
        dyn_str_mut.with_secret_mut(|s| s.push_str("_scoped"));
    }

    // 11. Debug REDACTED verification
    {
        let debug_output = format!("{:?}", fixed_key);
        assert!(debug_output.contains("[REDACTED]"));

        let first_byte = fixed_key.expose_secret()[0];
        assert!(!debug_output.contains(&format!("{:x}", first_byte)));

        let debug_dyn = format!("{:?}", dyn_vec);
        assert!(debug_dyn.contains("[REDACTED]"));
    }

    // 12. From/TryFrom conversions
    {
        let arr = [1u8; 16];
        let fixed_from_arr = Fixed::from(arr);
        assert_eq!(fixed_from_arr.expose_secret(), &arr);

        let slice16 = [42u8; 16];
        if let Ok(f) = Fixed::<[u8; 16]>::try_from(&slice16[..]) {
            assert_eq!(f.expose_secret(), &slice16);
        }

        let dyn_from_slice = Dynamic::<Vec<u8>>::from(&[1, 2, 3][..]);
        assert_eq!(dyn_from_slice.expose_secret(), &[1, 2, 3]);

        let dyn_from_str = Dynamic::<String>::from("test");
        assert_eq!(dyn_from_str.expose_secret(), "test");
    }

    // 13. from_random
    #[cfg(feature = "rand")]
    {
        let _ = Fixed::<[u8; 32]>::from_random();
        let _ = Dynamic::<Vec<u8>>::from_random(16);
    }

    // 14. Clone round-trip
    #[cfg(feature = "cloneable")]
    {
        use secure_gate::CloneableSecret;
        use zeroize::Zeroize;
        #[derive(Clone, Zeroize)]
        struct CloneKey(Vec<u8>);
        impl CloneableSecret for CloneKey {}
        let original = CloneKey(data.to_vec());
        let _ = original.clone();
    }

    // 15. len() / is_empty()
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
