// fuzz/fuzz_targets/parsing.rs
//
// Fuzz target for all parsing paths — Dynamic<String>, Dynamic<Vec<u8>>, and extreme allocation stress
// (v0.5.0 – SecureStr, SecureBytes, SecurePassword, etc. are gone; use Dynamic<T> + Fixed<T>)
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::Dynamic;
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec};

const MAX_LEN: usize = 1_000_000; // 1MB cap to avoid OOM

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
    let dyn_bytes = dyn_vec.clone();
    let _ = dyn_bytes.len();

    // 2. UTF-8 path — only if valid
    let s = dyn_str.expose_secret().clone();
    let dyn_str_new = Dynamic::<String>::new(s.clone());
    let _ = dyn_str_new.len();

    // Stress: clone + to_string
    let cloned = dyn_str_new.clone();
    let _ = cloned.expose_secret().to_string();
    drop(cloned);

    // Edge cases with emoji glory
    let _ = Dynamic::<String>::new("".to_string());
    let _ = Dynamic::<String>::new("hello world".to_string());
    let _ = Dynamic::<String>::new("grinning face rocket".to_string());

    // Allocation stress on long valid strings
    if s.len() > 1_000 {
        let _ = Dynamic::<String>::new(s.clone());
    }
    if s.len() > 5_000 {
        let _ = Dynamic::<String>::new(s.clone());
    }

    // 3. Mutation stress — lossy UTF-8 → owned String → Dynamic<String>
    let owned = s.clone(); // Reuse fuzzed string
    let mut dyn_str_mut = Dynamic::<String>::new(owned);
    dyn_str_mut.expose_secret_mut().push('!');
    dyn_str_mut.expose_secret_mut().push_str("_fuzz");
    dyn_str_mut.expose_secret_mut().clear();
    let _ = dyn_str_mut.finish_mut();

    // 4. Extreme allocation stress — repeated data
    let repeated_data = dyn_vec.expose_secret().clone();
    for i in 1..=10 {
        if repeated_data.len().saturating_mul(i as usize) > MAX_LEN {
            break;
        }
        let repeated = std::iter::repeat(repeated_data.as_slice())
            .take(i.min(100))
            .flatten()
            .copied()
            .collect::<Vec<u8>>();
        let repeated_dyn: Dynamic<Vec<u8>> = Dynamic::new(repeated);
        let _ = repeated_dyn.len();
    }

    // Final drop — triggers zeroization when feature enabled
    drop(dyn_str_mut);
});
