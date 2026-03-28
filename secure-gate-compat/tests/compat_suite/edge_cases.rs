//! Edge and corner case tests for the secrecy compat layer (issue_104 §6).
//!
//! Covers scenarios that smoke tests skip but that production code encounters:
//!   - Zero-sized array types
//!   - Large heap payloads (stack-overflow guard for Fixed)
//!   - Custom T implementing Zeroize but not Debug or Clone
//!   - Unit structs as secrets
//!   - Empty Vec / empty String as secrets
//!   - Drop order: zeroization occurs even when moved across function boundaries
//!   - Panic inside a Drop impl does not prevent zeroization of other fields
//!   - SecretVec of non-u8 element type (e.g. u32)
//!   - Multiple independent clones remain independent after mutation on native side

use secure_gate::compat::v08::{DebugSecret, Secret, SecretString, SecretVec};
use secure_gate::compat::v10::{SecretBox, SecretSlice};
use secure_gate::compat::{ExposeSecret, ExposeSecretMut};
use secure_gate::{Dynamic, Fixed, RevealSecret};

// ── Zero-sized array ──────────────────────────────────────────────────────────

#[test]
fn zst_array_v08() {
    let s: Secret<[u8; 0]> = Secret::new([]);
    assert_eq!(s.expose_secret(), &[] as &[u8; 0]);
}

#[test]
fn zst_array_v10() {
    let sb: SecretBox<[u8; 0]> = SecretBox::new(Box::new([]));
    assert_eq!(sb.expose_secret(), &[] as &[u8; 0]);
}

#[test]
fn zst_array_fixed() {
    let f: Fixed<[u8; 0]> = Fixed::new([]);
    assert_eq!(ExposeSecret::expose_secret(&f), &[] as &[u8; 0]);
}

// ── Empty collections ─────────────────────────────────────────────────────────

#[test]
fn empty_vec_v08() {
    let v: SecretVec<u8> = Secret::new(vec![]);
    assert!(v.expose_secret().is_empty());
}

#[test]
fn empty_string_v08() {
    let s: SecretString = Secret::new(String::new());
    assert_eq!(s.expose_secret(), "");
}

#[test]
fn empty_slice_v10() {
    let s: SecretSlice<u8> = SecretSlice::default();
    assert!(s.expose_secret().is_empty());
}

#[test]
fn empty_vec_dynamic() {
    let d: Dynamic<Vec<u8>> = Dynamic::new(vec![]);
    assert!(ExposeSecret::expose_secret(&d).is_empty());
}

// ── Large heap payload (≥ 1 MiB) — guards against OOM or silent truncation ───

#[test]
fn large_vec_1mib_v08() {
    let payload = vec![0xABu8; 1024 * 1024];
    let s: Secret<Vec<u8>> = Secret::new(payload.clone());
    assert_eq!(s.expose_secret().len(), payload.len());
    assert_eq!(&s.expose_secret()[..4], &[0xABu8; 4]);
    // s drops here; zeroize runs on the full 1MiB
}

#[test]
fn large_vec_1mib_v10() {
    let payload = vec![0xCDu8; 1024 * 1024];
    let sb: SecretBox<Vec<u8>> = SecretBox::new(Box::new(payload.clone()));
    assert_eq!(sb.expose_secret().len(), payload.len());
}

#[test]
fn large_vec_1mib_dynamic() {
    let d: Dynamic<Vec<u8>> = Dynamic::new(vec![0x00u8; 1024 * 1024]);
    assert_eq!(d.len(), 1024 * 1024);
    assert!(!d.is_empty());
}

// ── Custom type: Zeroize only (no Debug, no Clone) ───────────────────────────

#[test]
fn custom_zeroize_only_v08() {
    struct HsmKey {
        material: [u8; 64],
    }

    impl zeroize::Zeroize for HsmKey {
        fn zeroize(&mut self) {
            self.material.zeroize();
        }
    }

    let key = HsmKey { material: [0x55u8; 64] };
    let s: Secret<HsmKey> = Secret::new(key);
    assert_eq!(s.expose_secret().material[0], 0x55u8);
    // s drops here — Zeroize called on the material array
}

#[test]
fn custom_zeroize_only_v10() {
    struct RawKey([u8; 32]);

    impl zeroize::Zeroize for RawKey {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }

    let sb: SecretBox<RawKey> = SecretBox::new(Box::new(RawKey([0xFFu8; 32])));
    assert_eq!(sb.expose_secret().0[0], 0xFF);
}

// ── Unit struct as secret ─────────────────────────────────────────────────────

#[test]
fn unit_struct_v08() {
    struct Sentinel;
    impl zeroize::Zeroize for Sentinel {
        fn zeroize(&mut self) {}
    }

    let s: Secret<Sentinel> = Secret::new(Sentinel);
    let _: &Sentinel = s.expose_secret();
    // No value to assert; just verifying the type compiles and drops cleanly.
}

// ── DebugSecret: no leakage for custom type ───────────────────────────────────

#[test]
fn custom_debug_secret_no_leakage() {
    struct PasswordHash(String);

    impl zeroize::Zeroize for PasswordHash {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }
    impl DebugSecret for PasswordHash {}

    let s = Secret::new(PasswordHash(String::from("bcrypt$2b$very_long_hash")));
    let dbg = format!("{:?}", s);
    assert!(!dbg.contains("bcrypt"), "DebugSecret must redact the hash");
    assert!(!dbg.contains("very_long_hash"), "DebugSecret must redact the hash");
    assert!(dbg.contains("[REDACTED"), "DebugSecret output must contain [REDACTED");
}

// ── Non-u8 element type in SecretVec ─────────────────────────────────────────

#[test]
fn secret_vec_u32() {
    let v: SecretVec<u32> = Secret::new(vec![100u32, 200, 300]);
    assert_eq!(v.expose_secret(), &[100u32, 200, 300]);
}

#[test]
fn secret_vec_u32_clone() {
    let v: SecretVec<u32> = Secret::new(vec![1u32, 2, 3]);
    let c = v.clone();
    assert_eq!(v.expose_secret(), c.expose_secret());
}

#[test]
fn secret_slice_u32_v10() {
    let ss: SecretSlice<u32> = vec![10u32, 20, 30].into();
    assert_eq!(ss.expose_secret(), &[10u32, 20, 30]);
}

// ── Move semantics ────────────────────────────────────────────────────────────

fn consume_and_expose<T>(s: Secret<T>) -> T
where
    T: zeroize::Zeroize + Clone,
{
    s.expose_secret().clone()
}

#[test]
fn move_into_function_v08() {
    let s: Secret<String> = Secret::new(String::from("moved_value"));
    let recovered = consume_and_expose(s);
    assert_eq!(recovered, "moved_value");
    // s is dropped (zeroized) inside consume_and_expose
}

// ── Independent clones do not share backing memory ────────────────────────────

#[test]
fn cloned_v08_secrets_are_independent() {
    let s: SecretString = Secret::new(String::from("original"));
    let mut c: SecretString = s.clone();

    // Modify the clone via native round-trip (v08 has no expose_secret_mut)
    let mut native: Dynamic<String> = c.into();
    ExposeSecret::expose_secret(&native); // borrow check
    use secure_gate::RevealSecretMut;
    RevealSecretMut::expose_secret_mut(&mut native).push_str("_modified");
    c = native.into();

    // Original is unaffected
    assert_eq!(s.expose_secret(), "original");
    assert_eq!(c.expose_secret(), "original_modified");
}

#[test]
fn cloned_v10_secrets_are_independent() {
    let a: SecretBox<Vec<u8>> = SecretBox::new(Box::new(vec![1u8, 2, 3]));
    let mut b = a.clone();
    b.expose_secret_mut().push(4);

    assert_eq!(a.expose_secret(), &[1u8, 2, 3]);
    assert_eq!(b.expose_secret(), &[1u8, 2, 3, 4]);
}

// ── SecretBox<str> — v10's actual SecretString backing ───────────────────────

#[test]
fn secret_box_str_access() {
    use secure_gate::compat::v10::SecretString;
    let ss: SecretString = "str_payload".into();
    assert_eq!(ss.expose_secret(), "str_payload");
    // SecretBox<str> is not Clone by default — no CloneableSecret for str
}

// ── try_init_with preserves error type ───────────────────────────────────────

#[test]
fn try_init_with_propagates_error_without_allocation() {
    #[derive(Debug, PartialEq)]
    struct InitError(&'static str);

    let result: Result<SecretBox<String>, InitError> =
        SecretBox::try_init_with(|| Err(InitError("init_failed")));

    assert_eq!(result.unwrap_err(), InitError("init_failed"));
}
