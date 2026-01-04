// fuzz/fuzz_targets/expose.rs
// Fully updated for v0.6.0 — no Deref, explicit exposure only
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{Dynamic, Fixed};
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec, FuzzFixed32};

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
});
