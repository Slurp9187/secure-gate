// fuzz/fuzz_targets/parsing.rs
//
// Fuzz target for all parsing/conversion paths — Dynamic<String>, Dynamic<Vec<u8>>,
// Fixed<[u8;N]>, From/TryFrom conversions, UTF-8 boundary stress, len consistency.
// Updated for v0.8.0: explicit exposure everywhere, no Deref.
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, Fixed, ExposeSecret, ExposeSecretMut};
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec};

// 256 KB cap — large enough for allocation stress, small enough for CI
const MAX_LEN: usize = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
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

    if dyn_vec.expose_secret().len() > MAX_LEN {
        return;
    }

    // 1. Dynamic<Vec<u8>> — raw arbitrary bytes (no UTF-8 required)
    {
        let dyn_bytes: Dynamic<Vec<u8>> = Dynamic::new(dyn_vec.expose_secret().clone());
        let _ = dyn_bytes.expose_secret().len();
        drop(dyn_bytes);
    }

    // 2. len() / is_empty() consistency checks
    {
        let vec_len = dyn_vec.len();
        assert_eq!(
            vec_len,
            dyn_vec.expose_secret().len(),
            "len() mismatch on Dynamic<Vec<u8>>"
        );
        assert_eq!(dyn_vec.is_empty(), vec_len == 0);

        let str_len = dyn_str.len();
        assert_eq!(
            str_len,
            dyn_str.expose_secret().len(),
            "len() mismatch on Dynamic<String>"
        );
        assert_eq!(dyn_str.is_empty(), str_len == 0);
    }

    // 3. UTF-8 path — clone the string, wrap, mutate
    {
        let s = dyn_str.expose_secret().clone();
        let dyn_str_new = Dynamic::<String>::new(s.clone());
        assert_eq!(dyn_str_new.len(), s.len());

        let cloned: Dynamic<String> = Dynamic::new(dyn_str_new.expose_secret().clone());
        let _ = cloned.expose_secret().to_string();
        drop(cloned);

        // Allocation stress on long strings (cap iterations to stay fast)
        for factor in 1..=5_usize {
            if s.len().saturating_mul(factor) > MAX_LEN {
                break;
            }
            let repeated: String = s.chars().cycle().take(s.len() * factor).collect();
            let _ = Dynamic::<String>::new(repeated);
        }
    }

    // 4. UTF-8 boundary stress — try to interpret raw fuzz bytes as UTF-8
    {
        if let Ok(s) = core::str::from_utf8(data) {
            let dyn_from_str = Dynamic::<String>::new(s.to_string());
            let _ = dyn_from_str.expose_secret().len();
        }

        // Attempt lossy UTF-8 by feeding bytes through String::from_utf8_lossy
        let lossy_str = String::from_utf8_lossy(data).into_owned();
        let dyn_lossy = Dynamic::<String>::new(lossy_str);
        let _ = dyn_lossy.len();
    }

    // 5. From/TryFrom conversions for Fixed
    {
        // Fixed<[u8; N]> from array
        let arr4 = [data[0], data[0].wrapping_add(1), 0x00, 0xFF];
        let fixed4 = Fixed::from(arr4);
        assert_eq!(fixed4.expose_secret(), &arr4);

        // TryFrom<&[u8]> — exact size succeeds, wrong size fails
        if let Ok(fixed_from_slice) = Fixed::<[u8; 1]>::try_from(&data[..1]) {
            assert_eq!(fixed_from_slice.expose_secret(), &[data[0]]);
        }

        // TryFrom with wrong size must return Err, not panic
        let too_short: &[u8] = &[];
        assert!(Fixed::<[u8; 4]>::try_from(too_short).is_err());

        // Correct-size TryFrom
        if data.len() >= 4 {
            let slice4 = &data[..4];
            if let Ok(f) = Fixed::<[u8; 4]>::try_from(slice4) {
                assert_eq!(f.expose_secret(), slice4);
            }
        }
    }

    // 6. From/TryFrom conversions for Dynamic
    {
        // Dynamic from &[u8]
        let dyn_from_slice = Dynamic::<Vec<u8>>::from(data);
        assert_eq!(dyn_from_slice.expose_secret(), data);

        // Dynamic from &str
        let sample = "hello fuzzer";
        let dyn_from_str = Dynamic::<String>::from(sample);
        assert_eq!(dyn_from_str.expose_secret(), sample);

        // Dynamic from owned Vec<u8>
        let owned = data.to_vec();
        let dyn_from_owned: Dynamic<Vec<u8>> = Dynamic::from(owned.clone());
        assert_eq!(dyn_from_owned.expose_secret(), &owned);
    }

    // 7. Mutation stress
    {
        let s = dyn_str.expose_secret().clone();
        let mut dyn_str_mut = Dynamic::<String>::new(s);
        dyn_str_mut.expose_secret_mut().push('!');
        dyn_str_mut.expose_secret_mut().push_str("_fuzz");
        dyn_str_mut.expose_secret_mut().clear();
        dyn_str_mut.expose_secret_mut().shrink_to_fit();
        drop(dyn_str_mut);
    }

    // 8. Allocation stress — repeated data (capped to MAX_LEN)
    {
        let repeated_data = dyn_vec.expose_secret().clone();
        if !repeated_data.is_empty() {
            for factor in 1..=5_usize {
                if repeated_data.len().saturating_mul(factor) > MAX_LEN {
                    break;
                }
                let repeated = repeated_data.repeat(factor);
                let dyn_rep = Dynamic::<Vec<u8>>::new(repeated);
                let _ = dyn_rep.expose_secret().len();
            }
        }
    }

    // 9. Edge cases: empty, single-byte, max-byte
    {
        let _ = Dynamic::<Vec<u8>>::new(vec![]);
        let _ = Dynamic::<Vec<u8>>::new(vec![0x00]);
        let _ = Dynamic::<Vec<u8>>::new(vec![0xFF]);
        let _ = Dynamic::<String>::new(String::new());
        let _ = Dynamic::<String>::new("hello world".to_string());
        let _ = Dynamic::<String>::new("🔐 secret 🔑".to_string());
    }
});
