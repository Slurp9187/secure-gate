// fuzz/fuzz_targets/expose.rs
//
// Fuzz target for exposing and mutating secure types

#![no_main]
use libfuzzer_sys::fuzz_target;

use secure_gate::{secure, Secure, SecureBytes, SecurePassword, SecurePasswordBuilder, SecureStr};
use secure_gate::{ExposeSecret, ExposeSecretMut};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. Secure<Vec<u8>> – mutable, growable
    let mut vec_sec = Secure::<Vec<u8>>::new(data.to_vec());
    vec_sec.expose_mut().reverse();
    vec_sec.expose_mut().truncate(data.len() % 64);
    vec_sec.expose_mut().extend_from_slice(b"fuzz");
    vec_sec.finish_mut();

    // 2. Immutable byte/string slices
    let _bytes: SecureBytes = data.to_vec().into();
    let s = String::from_utf8_lossy(data);
    let _str: SecureStr = s.as_ref().into();

    // 3. SecurePassword – immutable str
    let pw: SecurePassword = s.as_ref().into();
    let _ = pw.expose_secret();

    // 4. SecurePasswordBuilder – the ONLY mutable string type
    let mut builder = SecurePasswordBuilder::from(s.to_string());
    {
        let inner = builder.expose_secret_mut();
        inner.push_str("fuzz");
        inner.push('X');
        inner.clear();
        inner.push_str(&s);
        inner.truncate(inner.len().saturating_sub(1));
        if !inner.is_empty() {
            inner.insert(0, 'Y');
        }
        inner.shrink_to_fit();
    }
    let _final_pw = builder.into_password();

    // 5. Fixed-size keys – SAFE version
    let key_bytes = if data.len() >= 32 {
        // Safe: only copy what actually exists, pad the rest with 0
        let mut arr = [0u8; 32];
        let copy_len = core::cmp::min(data.len(), 32);
        arr[..copy_len].copy_from_slice(&data[..copy_len]);
        arr
    } else {
        [0u8; 32] // short input → zero-padded key
    };
    let _key = secure!([u8; 32], key_bytes);
    let _nonce = secure!([u8; 12], [0u8; 12]);

    // 6. Clone / Default / into_inner
    let cloneable = Secure::<Vec<u8>>::new(vec![1, 2, 3]);
    let _ = cloneable.clone();
    let _default = Secure::<String>::default();
    let _inner: Vec<u8> = *cloneable.into_inner();
});
