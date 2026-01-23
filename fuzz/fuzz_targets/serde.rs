#![no_main]
use libfuzzer_sys::fuzz_target;
// #[cfg(feature = "encoding-base64")]
// use secure_gate::encoding::base64::Base64String;
// #[cfg(feature = "encoding-bech32")]
// use secure_gate::encoding::bech32::Bech32String;
// #[cfg(feature = "encoding-hex")]
// use secure_gate::encoding::hex::HexString;

use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut, Fixed};
use serde::Deserialize;
use serde_json;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    // Cap to avoid instant OOM – serde can allocate aggressively
    if data.len() > 1_000_000 {
        return;
    }

    // Helper to try deserialize without panicking fuzzer
    macro_rules! try_deser {
        ($ty:ty, $data:expr) => {{
            let _ = serde_json::from_slice::<$ty>($data);
        }};
    }

    // 1. Core generics
    try_deser!(Fixed<[u8; 32]>, data);
    try_deser!(Dynamic<String>, data);
    try_deser!(Dynamic<Vec<u8>>, data);

    // 3. Encoding wrappers (validation + zeroize on invalid) - commented out as encoding types not implemented
    // #[cfg(feature = "encoding-hex")]
    // try_deser!(HexString, data);
    // #[cfg(feature = "encoding-base64")]
    // try_deser!(Base64String, data);
    // #[cfg(feature = "encoding-bech32")]
    // try_deser!(Bech32String, data);

    // 4. Nested / complex (stress visitor + allocation)
    try_deser!(Vec<Dynamic<String>>, data);
    try_deser!(Option<Fixed<[u8; 16]>>, data);

    // 5. Post-deserialize stress (if successful, mutate + drop to hit zeroize)
    if let Ok(secret) = serde_json::from_slice::<Dynamic<Vec<u8>>>(data) {
        let mut s = secret;
        if let Some(v) = s.expose_secret_mut().get_mut(0) {
            *v = 0xFF;
        }
        #[cfg(feature = "zeroize")]
        if data.get(0).copied().unwrap_or(0) % 2 == 0 {
            s.zeroize();
        }
        drop(s);
    }
});
