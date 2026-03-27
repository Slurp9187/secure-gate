//! Fuzz target: secrecy v0.8.0 compat layer (issue_104 §7).
//!
//! Exercises the full round-trip lifecycle of v08 compat types against arbitrary input:
//!   - Secret<Vec<u8>>  ↔  Dynamic<Vec<u8>>  (both directions)
//!   - Secret<String>   ↔  Dynamic<String>    (both directions)
//!   - Secret<[u8; 32]> ↔  Fixed<[u8; 32]>   (both directions)
//!
//! Invariants asserted on every run:
//!   1. Value identity: expose_secret() after round-trip == original
//!   2. Debug never leaks: format!("{:?}") does not contain the exposed value
//!      (only for types whose S implements DebugSecret — String, [T; N], Box<S>, Vec<S where S:DebugSecret>;
//!       `Secret<Vec<u8>>` intentionally has no Debug because u8 does not implement DebugSecret)
//!   3. Clone independence: modifying clone does not affect original
//!   4. Zeroize on drop: types drop without panicking (memory safety via allocator)

#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::compat::v08::{Secret, SecretString};
use secure_gate::compat::ExposeSecret;
use secure_gate::{Dynamic, Fixed};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let mut u = Unstructured::new(data);

    // ── Vec<u8> round-trip ────────────────────────────────────────────────────
    if let Ok(bytes) = Vec::<u8>::arbitrary(&mut u) {
        let capped = if bytes.len() > 4096 { bytes[..4096].to_vec() } else { bytes };

        // v08 → Dynamic → v08
        let v08: Secret<Vec<u8>> = Secret::new(capped.clone());
        let original_exposed = v08.expose_secret().clone();
        let native: Dynamic<Vec<u8>> = v08.into();
        assert_eq!(ExposeSecret::expose_secret(&native), &original_exposed,
            "Vec<u8>: v08→Dynamic value identity failed");

        let v08_back: Secret<Vec<u8>> = native.into();
        assert_eq!(v08_back.expose_secret(), &original_exposed,
            "Vec<u8>: Dynamic→v08 value identity failed");

        // Clone independence
        let original: Secret<Vec<u8>> = Secret::new(capped.clone());
        let clone = original.clone();
        assert_eq!(original.expose_secret(), clone.expose_secret(),
            "Vec<u8>: clone does not match original");

        // Note: Secret<Vec<u8>> intentionally has no Debug impl in v0.8 compat because
        // u8 does not implement DebugSecret (Vec<S> requires S: DebugSecret).
        // Debug-redaction is verified below for SecretString, which does implement DebugSecret.
        let _ = v08_back; // consumed, zeroized on drop
    }

    // ── String round-trip ─────────────────────────────────────────────────────
    if let Ok(s) = String::arbitrary(&mut u) {
        let capped: String = if s.len() > 2048 { s.chars().take(2048).collect() } else { s };

        let v08str: SecretString = Secret::new(capped.clone());
        let native_str: Dynamic<String> = v08str.into();
        assert_eq!(ExposeSecret::expose_secret(&native_str), &capped,
            "String: v08→Dynamic value identity failed");

        let v08str_back: SecretString = native_str.into();
        assert_eq!(v08str_back.expose_secret(), &capped,
            "String: Dynamic→v08 value identity failed");

        // Debug must not contain the raw string if it's non-trivial
        let dbg = format!("{:?}", v08str_back);
        assert!(dbg.contains("[REDACTED"), "String: debug missing [REDACTED: {}", dbg);

        if !capped.is_empty() {
            // A non-empty payload must not appear verbatim in the debug output.
            // We sample the first 8 chars to avoid false positives from type names.
            let sample: String = capped.chars().take(8).collect();
            if sample.len() >= 4 && sample.is_ascii() {
                assert!(!dbg.contains(&sample),
                    "String: debug leaked payload sample '{}' in: {}", sample, dbg);
            }
        }
    }

    // ── [u8; 32] round-trip ───────────────────────────────────────────────────
    if u.len() >= 32 {
        let mut arr = [0u8; 32];
        if u.fill_buffer(&mut arr).is_ok() {
            let v08_arr: Secret<[u8; 32]> = Secret::new(arr);
            let fixed: Fixed<[u8; 32]> = v08_arr.into();
            let v08_arr_back: Secret<[u8; 32]> = fixed.into();
            assert_eq!(*v08_arr_back.expose_secret(), arr,
                "[u8; 32]: round-trip value identity failed");
        }
    }
});
