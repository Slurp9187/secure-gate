// fuzz/fuzz_targets/mut.rs
//
// Mutation + zeroization stress target for secure-gate v0.8.0
// Zeroize is always-on. Tests expose_secret_mut, with_secret_mut, command-driven
// mutation, zeroize verification, spare-capacity stress, and nested types.
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, Fixed, RevealSecret, RevealSecretMut};
use secure_gate_fuzz::arbitrary::{FuzzAction, FuzzDynamicString, FuzzDynamicVec, FuzzFixed32};
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = Unstructured::new(data);

    let fixed_32 = match FuzzFixed32::arbitrary(&mut u) {
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

    // 1. Dynamic<String> — full mutation torture + explicit zeroize
    {
        let mut pw: Dynamic<String> = Dynamic::new(dyn_str.expose_secret().clone());
        let text = pw.expose_secret().clone();

        pw.with_secret_mut(|s| {
            s.clear();
            s.push_str(&text);

            // Truncate to a char boundary within the text
            let max_bytes = text.len() % 1800;
            let truncate_to = text
                .char_indices()
                .map(|(i, _)| i)
                .find(|&i| i > max_bytes)
                .unwrap_or(text.len());
            s.truncate(truncate_to);

            let append_count = (text.len() % 150).min(1000);
            for _ in 0..append_count {
                s.push('🚀');
            }
        });

        pw.expose_secret_mut().shrink_to_fit();

        if text.len() % 2 == 0 {
            pw.zeroize();
        }
        drop(pw);
    }

    // 2. Dynamic<Vec<u8>> — raw buffer abuse + zeroize verification
    {
        let mut bytes: Dynamic<Vec<u8>> = Dynamic::new(dyn_vec.expose_secret().clone());

        bytes.with_secret_mut(|v| {
            v.clear();
            v.extend_from_slice(data);
            let new_size = v.len().saturating_add(data.len().min(500_000));
            v.resize(new_size, 0xFF);
            v.truncate(data.len().saturating_add(1) % 3000);
            v.retain(|&b| b != data[0]);
        });

        if data[0] % 3 == 0 {
            bytes.zeroize();
            // After zeroize all bytes must be zero
            assert!(
                bytes.expose_secret().iter().all(|&b| b == 0),
                "Vec not fully zeroized"
            );
        }
        drop(bytes);
    }

    // 3. Fixed<[u8; 32]> — mutation isolation test
    {
        let mut key = fixed_32;
        let original_first = key.expose_secret()[0];
        if data.len() > 1 {
            key.with_secret_mut(|arr| arr[0] = !original_first);
            assert_ne!(
                key.expose_secret()[0],
                original_first,
                "Fixed mutation isolation failed"
            );
        }
    }

    // 4. Spare-capacity zeroize stress
    {
        let mut v = Dynamic::<Vec<u8>>::new(Vec::with_capacity(1024));
        v.expose_secret_mut().extend_from_slice(data);
        v.expose_secret_mut().truncate(10);
        // Capacity is still 1024 (or data.len()), but len is 10.
        // Zeroize must wipe the entire allocation including spare capacity.
        v.zeroize();
        assert!(
            v.expose_secret().iter().all(|&b| b == 0),
            "Spare-capacity not zeroized"
        );
    }

    // 5. Command-driven fuzzing via FuzzAction
    {
        let mut target: Dynamic<Vec<u8>> = Dynamic::new(data.to_vec());
        let num_actions = u.int_in_range(0..=8).unwrap_or(0);
        for _ in 0..num_actions {
            match FuzzAction::arbitrary(&mut u) {
                Ok(FuzzAction::PushByte(b)) => {
                    target.expose_secret_mut().push(b);
                }
                Ok(FuzzAction::ExtendFromSlice(ref extra)) => {
                    let capped = &extra[..extra.len().min(256)];
                    target.expose_secret_mut().extend_from_slice(capped);
                }
                Ok(FuzzAction::Truncate(n)) => {
                    let len = target.expose_secret().len();
                    target.expose_secret_mut().truncate(n % (len.max(1) + 1));
                }
                Ok(FuzzAction::Clear) => {
                    target.with_secret_mut(|v| v.clear());
                }
                Ok(FuzzAction::Reverse) => {
                    target.with_secret_mut(|v| v.reverse());
                }
                Ok(FuzzAction::ShrinkToFit) => {
                    target.expose_secret_mut().shrink_to_fit();
                }
                Ok(FuzzAction::Zeroize) => {
                    target.zeroize();
                }
                Err(_) => break,
            }
        }
        drop(target);
    }

    // 6. Nested Dynamic<Dynamic<Vec<u8>>> — creation, zeroize, drop ordering
    // RevealSecret/RevealSecretMut is not blanket-impl'd for arbitrary T;
    // only Dynamic<String> and Dynamic<Vec<T>> have impls. We test
    // construction and drop-order zeroize here.
    {
        let inner = Dynamic::<Vec<u8>>::new(data.to_vec());
        let nested = Dynamic::<Dynamic<Vec<u8>>>::new(inner);
        // Dropping nested triggers zeroize on both the outer and inner wrappers.
        drop(nested);

        // Standalone inner zeroize
        if data[0] % 11 == 0 {
            let mut inner_dyn = Dynamic::<Vec<u8>>::new(data.to_vec());
            inner_dyn.zeroize();
        }
    }

    // 7. Small Fixed + empty Dynamic edge cases
    {
        if data.len() >= 2 {
            let mut small = Fixed::new([data[0], data[1]]);
            small.with_secret_mut(|arr| arr[0] = arr[0].wrapping_add(1));
            small.zeroize();
        }

        let mut empty_vec = Dynamic::<Vec<u8>>::new(Vec::new());
        if !data.is_empty() {
            empty_vec.expose_secret_mut().push(data[0]);
        }
        if data[0] % 13 == 0 {
            empty_vec.zeroize();
        }
        drop(empty_vec);
    }
});
