// fuzz/fuzz_targets/parsing.rs
//
// Fuzz target for all parsing/conversion paths — Dynamic<String>, Dynamic<Vec<u8>>,
// Fixed<[u8;N]>, From/TryFrom conversions, UTF-8 boundary stress, len consistency.
// Updated for v0.8.0: explicit exposure everywhere, no Deref.

#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, RevealSecret, RevealSecretMut, Fixed};
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

    // 1. Dynamic<Vec<u8>> — raw arbitrary bytes
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

    // 3. UTF-8 path — clone the string, wrap, mutate + repeated-string stress
    {
        let s = dyn_str.expose_secret().clone();
        let dyn_str_new = Dynamic::<String>::new(s.clone());
        assert_eq!(dyn_str_new.len(), s.len());

        let cloned: Dynamic<String> = Dynamic::new(dyn_str_new.expose_secret().clone());
        let _ = cloned.expose_secret().to_string();
        drop(cloned);

        for factor in 1..=5_usize {
            if s.len().saturating_mul(factor) > MAX_LEN {
                break;
            }
            let repeated: String = s.chars().cycle().take(s.len() * factor).collect();
            let _ = Dynamic::<String>::new(repeated);
        }
    }

    // 4. UTF-8 boundary stress (raw fuzz bytes)
    {
        if let Ok(s) = core::str::from_utf8(data) {
            let _ = Dynamic::<String>::new(s.to_string());
        }
        let lossy_str = String::from_utf8_lossy(data).into_owned();
        let _ = Dynamic::<String>::new(lossy_str);
    }

    // 5. From/TryFrom conversions for Fixed
    {
        let arr4 = [data[0], data[0].wrapping_add(1), 0x00, 0xFF];
        let fixed4 = Fixed::from(arr4);
        assert_eq!(fixed4.expose_secret(), &arr4);

        // TryFrom exact size
        if let Ok(fixed_from_slice) = Fixed::<[u8; 1]>::try_from(&data[..1]) {
            assert_eq!(fixed_from_slice.expose_secret(), &[data[0]]);
        }

        // TryFrom wrong size MUST return Err (this was the crashing path)
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
        let dyn_from_slice = Dynamic::<Vec<u8>>::from(data);
        assert_eq!(dyn_from_slice.expose_secret(), data);

        let sample = "hello fuzzer";
        let dyn_from_str = Dynamic::<String>::from(sample);
        assert_eq!(dyn_from_str.expose_secret(), sample);

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

    // 8. Allocation stress — repeated data
    {
        let repeated_data = dyn_vec.expose_secret().clone();
        if !repeated_data.is_empty() {
            for factor in 1..=5_usize {
                if repeated_data.len().saturating_mul(factor) > MAX_LEN {
                    break;
                }
                let repeated = repeated_data.repeat(factor);
                let _ = Dynamic::<Vec<u8>>::new(repeated);
            }
        }
    }

    // 9. Edge cases
    {
        let _ = Dynamic::<Vec<u8>>::new(vec![]);
        let _ = Dynamic::<Vec<u8>>::new(vec![0x00]);
        let _ = Dynamic::<Vec<u8>>::new(vec![0xFF]);
        let _ = Dynamic::<String>::new(String::new());
        let _ = Dynamic::<String>::new("hello world".to_string());
        let _ = Dynamic::<String>::new("🔐 secret 🔑".to_string());
    }
});
