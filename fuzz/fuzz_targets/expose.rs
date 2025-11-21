// fuzz/fuzz_targets/expose.rs
//
// Fuzz SecureGate<T> expose/expose_mut usage across all public types

#![no_main]
use libfuzzer_sys::fuzz_target;

use secure_gate::{SecureBytes, SecureGate, SecureStr};

#[cfg(feature = "zeroize")]
use secure_gate::{ExposeSecret, ExposeSecretMut, SecurePassword, SecurePasswordBuilder};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. Growable Vec<u8> — heavy mutation stress
    let mut vec_sec = SecureGate::new(data.to_vec());
    vec_sec.expose_mut().reverse();
    vec_sec.expose_mut().truncate(data.len() % 64);
    vec_sec.expose_mut().extend_from_slice(b"fuzz");
    vec_sec.expose_mut().shrink_to_fit();

    // 2. SecureBytes — heap-backed unsized slice
    let _bytes: SecureBytes = data.to_vec().into();

    // 3. SecureStr — owned string → boxed str
    let owned = String::from_utf8_lossy(data).into_owned();
    let _str: SecureStr = owned.as_str().into();

    // 4. SecurePassword — immutable, zeroizing path
    #[cfg(feature = "zeroize")]
    {
        let pw: SecurePassword = owned.as_str().into();
        let _ = pw.expose().expose_secret();
    }

    // 5. SecurePasswordBuilder — mutable string builder
    #[cfg(feature = "zeroize")]
    {
        let mut builder = SecurePasswordBuilder::from(owned.clone());
        {
            let inner = builder.expose_mut().expose_secret_mut();
            inner.push_str("fuzz");
            inner.push('X');
            inner.clear();
            inner.push_str(&owned);

            if !inner.is_empty() {
                let last_len = inner.chars().next_back().map(|c| c.len_utf8()).unwrap_or(0);
                inner.truncate(inner.len().saturating_sub(last_len));
            }
            if !inner.is_empty() {
                inner.insert(0, 'Y');
            }
            inner.shrink_to_fit();
        }
        let _final_pw = builder.into_password();
    }

    // 6. Fixed-size heap keys
    {
        let mut key_arr = [0u8; 32];
        let copy_len = core::cmp::min(data.len(), 32);
        key_arr[..copy_len].copy_from_slice(&data[..copy_len]);
        let _key = SecureGate::new(key_arr);
    }
    {
        let mut nonce_arr = [0u8; 12];
        let copy_len = core::cmp::min(data.len(), 12);
        nonce_arr[..copy_len].copy_from_slice(&data[..copy_len]);
        let _nonce = SecureGate::new(nonce_arr);
    }

    // 7. Clone + Default + into_inner sanity
    let cloneable = SecureGate::new(vec![1u8, 2, 3]);
    let _ = cloneable.clone();
    let _default = SecureGate::<String>::default();

    // into_inner only exists when zeroize is enabled
    #[cfg(feature = "zeroize")]
    let _inner: Box<Vec<u8>> = cloneable.into_inner();

    // 8. finish_mut() helpers
    {
        let mut v = SecureGate::new(vec![0u8; 1000]);
        v.expose_mut().truncate(10);
        let _ = v.finish_mut();
    }
    {
        let mut s = SecureGate::new(String::from("long string with excess capacity"));
        s.expose_mut().push_str("!!!");
        let _ = s.finish_mut();
    }
});
