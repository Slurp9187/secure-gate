//! Fuzz target: secrecy v0.10.1 compat layer (issue_104 §7).
//!
//! Exercises the full round-trip lifecycle of v10 compat types against arbitrary input:
//!   - SecretBox<Vec<u8>>  ↔  Dynamic<Vec<u8>>  (both directions)
//!   - SecretBox<String>   ↔  Dynamic<String>    (both directions)
//!   - SecretString        ↔  Dynamic<String>    (both directions)
//!   - SecretSlice<u8>     (construction, access, clone)
//!
//! Invariants asserted on every run:
//!   1. Value identity: expose_secret() after round-trip == original
//!   2. Debug always [REDACTED]: format!("{:?}") never contains the raw value
//!   3. Mutable access is preserved after conversion to Dynamic and back
//!   4. Clone independence: two clones do not share backing memory

#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::compat::v10::{SecretBox, SecretSlice, SecretString};
use secure_gate::compat::{ExposeSecret, ExposeSecretMut};
use secure_gate::Dynamic;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let mut u = Unstructured::new(data);

    // ── SecretBox<Vec<u8>> round-trip ─────────────────────────────────────────
    if let Ok(bytes) = Vec::<u8>::arbitrary(&mut u) {
        let capped = if bytes.len() > 4096 { bytes[..4096].to_vec() } else { bytes };

        let sb: SecretBox<Vec<u8>> = SecretBox::new(Box::new(capped.clone()));
        let native: Dynamic<Vec<u8>> = sb.into();
        assert_eq!(ExposeSecret::expose_secret(&native), &capped,
            "Vec<u8>: SecretBox→Dynamic identity failed");

        let sb_back: SecretBox<Vec<u8>> = native.into();
        assert_eq!(sb_back.expose_secret(), &capped,
            "Vec<u8>: Dynamic→SecretBox identity failed");

        // Clone independence
        let a: SecretBox<Vec<u8>> = SecretBox::new(Box::new(capped.clone()));
        let mut b = a.clone();
        b.expose_secret_mut().push(0xFF);
        assert_eq!(a.expose_secret(), &capped, "SecretBox<Vec> clone not independent");
        assert_eq!(b.expose_secret().len(), capped.len() + 1);
    }

    // ── SecretBox<String> + mutable access round-trip ─────────────────────────
    if let Ok(s) = String::arbitrary(&mut u) {
        let capped: String = if s.len() > 2048 { s.chars().take(2048).collect() } else { s };

        // init_with constructor
        let sb: SecretBox<String> = SecretBox::init_with(|| capped.clone());
        assert_eq!(sb.expose_secret(), &capped,
            "String: init_with value mismatch");

        // Mutable access: append and verify
        let mut sb_mut: SecretBox<String> = SecretBox::init_with(|| capped.clone());
        sb_mut.expose_secret_mut().push_str("_fuzz");
        let expected = format!("{}_fuzz", capped);
        assert_eq!(sb_mut.expose_secret(), &expected,
            "String: mutable access produced wrong value");

        // Round-trip via Dynamic
        let native: Dynamic<String> = sb_mut.into();
        assert_eq!(ExposeSecret::expose_secret(&native), &expected,
            "String: SecretBox→Dynamic after mutation identity failed");
        let sb_back: SecretBox<String> = native.into();
        assert_eq!(sb_back.expose_secret(), &expected,
            "String: Dynamic→SecretBox after mutation identity failed");

        // Debug invariant
        let dbg = format!("{:?}", sb_back);
        assert!(dbg.contains("[REDACTED]"),
            "String: SecretBox Debug missing [REDACTED]: {}", dbg);
        if capped.len() >= 4 {
            let sample: String = capped.chars().take(4).collect();
            if sample.is_ascii() && sample.chars().all(|c| c.is_alphanumeric()) {
                assert!(!dbg.contains(&sample),
                    "String: Debug leaked payload sample '{}' in: {}", sample, dbg);
            }
        }
    }

    // ── SecretString (= SecretBox<str>) round-trip ───────────────────────────
    if let Ok(s) = String::arbitrary(&mut u) {
        let capped: String = if s.len() > 512 { s.chars().take(512).collect() } else { s };

        let ss: SecretString = capped.clone().into();
        assert_eq!(ss.expose_secret(), capped.as_str(),
            "SecretString value mismatch");

        let native: Dynamic<String> = ss.into();
        assert_eq!(ExposeSecret::expose_secret(&native), &capped,
            "SecretString→Dynamic identity failed");

        let ss_back: SecretString = native.into();
        assert_eq!(ss_back.expose_secret(), capped.as_str(),
            "Dynamic→SecretString identity failed");

        // Debug invariant
        let dbg = format!("{:?}", ss_back);
        assert!(dbg.contains("[REDACTED]"),
            "SecretString Debug missing [REDACTED]: {}", dbg);
    }

    // ── SecretSlice<u8> (construction and access) ────────────────────────────
    if let Ok(bytes) = Vec::<u8>::arbitrary(&mut u) {
        let capped = if bytes.len() > 4096 { bytes[..4096].to_vec() } else { bytes };

        let ss: SecretSlice<u8> = capped.clone().into();
        assert_eq!(ss.expose_secret(), capped.as_slice(),
            "SecretSlice<u8> value mismatch");

        // Clone
        let sc = ss.clone();
        assert_eq!(ss.expose_secret(), sc.expose_secret(),
            "SecretSlice<u8> clone value mismatch");
    }

    // ── try_init_with: error path does not leak ───────────────────────────────
    {
        let result: Result<SecretBox<String>, &'static str> =
            SecretBox::try_init_with(|| Err("fuzz_error"));
        assert!(result.is_err(), "try_init_with Err path returned Ok");
    }
});
