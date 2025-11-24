// fuzz/fuzz_targets/expose.rs
// Updated for v0.5.5+ — expose_secret() returns raw references
#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{Dynamic, Fixed};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. Growable Vec<u8>
    let mut vec_dyn = Dynamic::<Vec<u8>>::new(data.to_vec());
    vec_dyn.reverse();
    vec_dyn.truncate(data.len() % 64);
    vec_dyn.extend_from_slice(b"fuzz");
    vec_dyn.shrink_to_fit();

    // 2. Fixed-size array
    let mut key_arr = [0u8; 32];
    let copy_len = core::cmp::min(data.len(), 32);
    key_arr[..copy_len].copy_from_slice(&data[..copy_len]);
    let mut fixed_key = Fixed::new(key_arr);
    fixed_key[0] = 0xFF;

    // 3. String handling
    let owned = String::from_utf8_lossy(data).into_owned();
    let mut dyn_str = Dynamic::<String>::new(owned.clone());
    dyn_str.push('!');

    // 4. Fixed-size nonce
    let mut nonce_arr = [0u8; 12];
    let copy_len = core::cmp::min(data.len(), 12);
    nonce_arr[..copy_len].copy_from_slice(&data[..copy_len]);
    let fixed_nonce = Fixed::new(nonce_arr);
    let _ = fixed_nonce.len();

    // 5. Clone + into_inner
    let cloneable = Dynamic::<Vec<u8>>::new(vec![1u8, 2, 3]);
    let _ = cloneable.clone();
    let _default = Dynamic::<String>::new(String::new());

    #[cfg(feature = "zeroize")]
    let _inner: Box<Vec<u8>> = cloneable.into_inner();

    // 6. finish_mut helpers
    {
        let mut v = Dynamic::<Vec<u8>>::new(vec![0u8; 1000]);
        v.truncate(10);
        let _ = v.finish_mut();
    }
    {
        let mut s = Dynamic::<String>::new("long string with excess capacity".to_string());
        s.push_str("!!!");
        let _ = s.finish_mut();
    }

    // 7. Borrowing stress — immutable
    {
        let view_imm1 = vec_dyn.expose_secret(); // &Vec<u8>
        let _ = view_imm1.len();
        let _ = view_imm1.as_slice().len();

        if data[0] % 2 == 0 {
            let view_imm2 = vec_dyn.expose_secret();
            let _ = view_imm2.as_slice()[0];
            let nested_ref: &[u8] = &**view_imm2;
            let _ = nested_ref.len();
        }
    }

    // 7. Borrowing stress — mutable
    {
        let view_mut = fixed_key.expose_secret_mut(); // &mut [u8; 32]
        view_mut[1] = 0x42;
        let _ = view_mut.as_ref();

        let str_imm = dyn_str.expose_secret(); // &String
        let _ = str_imm.as_str();
        let _ = str_imm.as_bytes();

        let str_mut = dyn_str.expose_secret_mut(); // &mut String
        str_mut.push('?');
        let _ = str_mut.as_str();
        let _ = str_mut.as_mut_str().as_bytes();

        // Nested reborrow — now correct
        let nested_mut: &mut String = &mut *str_mut;
        nested_mut.push('@');
    }

    // 8. Scoped drop stress — references drop automatically
    {
        let temp_dyn = Dynamic::<Vec<u8>>::new(vec![0u8; 10]);
        let temp_view = temp_dyn.expose_secret(); // &Vec<u8>
        let _ = temp_view.len();
        // Just let it go out of scope — no explicit drop needed
        let _ = temp_view;
        drop(temp_dyn);
    }
});
