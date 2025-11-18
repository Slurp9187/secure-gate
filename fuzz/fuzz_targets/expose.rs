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

    // 2. Immutable byte/string slices — SAFE version
    let _bytes: SecureBytes = data.to_vec().into();

    // CRITICAL FIX: Always own the string before converting to SecureStr
    let owned_string = String::from_utf8_lossy(data).into_owned();
    let _str: SecureStr = owned_string.as_str().into();

    // 3. SecurePassword – immutable
    let pw: SecurePassword = owned_string.as_str().into();
    let _ = pw.expose_secret();

    // 4. SecurePasswordBuilder – mutable string path
    let mut builder = SecurePasswordBuilder::from(owned_string.clone());
    {
        let inner = builder.expose_secret_mut();
        inner.push_str("fuzz");
        inner.push('X');
        inner.clear();
        inner.push_str(&owned_string);
        inner.truncate(inner.len().saturating_sub(1));
        if !inner.is_empty() {
            inner.insert(0, 'Y');
        }
        inner.shrink_to_fit();
    }
    let _final_pw = builder.into_password();

    // 5. Fixed-size keys – fully safe
    let key_bytes = {
        let mut arr = [0u8; 32];
        let copy_len = core::cmp::min(data.len(), 32);
        arr[..copy_len].copy_from_slice(&data[..copy_len]);
        arr
    };
    let _key = secure!([u8; 32], key_bytes);

    let nonce_bytes = {
        let mut arr = [0u8; 12];
        let copy_len = core::cmp::min(data.len(), 12);
        arr[..copy_len].copy_from_slice(&data[..copy_len]);
        arr
    };
    let _nonce = secure!([u8; 12], nonce_bytes);

    // 6. Clone / Default / into_inner
    let cloneable = Secure::<Vec<u8>>::new(vec![1, 2, 3]);
    let _ = cloneable.clone();
    let _default = Secure::<String>::default();
    let _inner: Vec<u8> = *cloneable.into_inner();
});
