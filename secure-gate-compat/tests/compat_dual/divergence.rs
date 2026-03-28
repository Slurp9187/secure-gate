//! Divergence tests: behaviors where compat shim and real `secrecy` differ.
//!
//! # Section A: Zeroization parity checks (runtime)
//!
//! Real `secrecy` also zeroizes on drop — both crates use the `zeroize` crate.
//! These tests confirm our shim zeroizes correctly. They are **parity assertions**,
//! not claims that our shim is stricter than real secrecy in this regard.
//!
//! # Section B: Shim-only stricter behaviors
//!
//! Our compat shim deliberately adds restrictions that real secrecy does not enforce:
//!
//! - No `Deref` impl — you must call `.expose_secret()` explicitly
//! - No `AsRef` impl — same reason
//! - `Debug` requires the `DebugSecret` marker trait — accidental `{:?}` fails to compile
//!
//! The compile-fail variants for these live in `tests/compile-fail/`:
//! - `compat_no_deref.rs` / `.stderr`
//! - `compat_no_asref.rs` / `.stderr`
//! - `compat_no_debug_without_marker.rs` / `.stderr`
//!
//! This file provides runtime documentation: code patterns that WORK as alternatives,
//! plus the zeroization correctness checks.

// ── Section A: Zeroization parity checks ─────────────────────────────────────
//
// NOTE: Real secrecy has identical zeroization behavior — both call `zeroize()` in `Drop`.
// These tests verify our shim's correctness, not superiority.

/// After dropping a `compat::v08::Secret<Vec<u8>>`, the memory is zeroed.
///
/// NOTE: real `secrecy 0.8.0` also calls `zeroize()` in `Drop`, producing the
/// same behavior. This test checks our shim is correct, not that it differs.
#[test]
fn compat_zeroize_on_drop_v08() {
    use secure_gate_compat::compat::v08::Secret;
    use secure_gate_compat::compat::ExposeSecret;

    // Allocate a secret and capture the heap address of its contents.
    let data = vec![0xFFu8; 32];
    let secret = Secret::new(data);

    // Read the pointer before drop (the Vec's internal buffer).
    let ptr = secret.expose_secret().as_ptr();
    let len = secret.expose_secret().len();

    // Verify non-zero content before drop.
    unsafe {
        for i in 0..len {
            assert_eq!(*ptr.add(i), 0xFF, "pre-drop byte {i} should be 0xFF");
        }
    }

    // Drop the secret — zeroize() runs in Drop.
    drop(secret);

    // After drop the buffer has been freed; we cannot safely read it.
    // Instead, we verify that the type called zeroize by using a custom Zeroize
    // wrapper that records whether zeroize() was called.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct ZeroizeWitness {
        called: Arc<AtomicBool>,
        _data: Vec<u8>,
    }
    impl zeroize::Zeroize for ZeroizeWitness {
        fn zeroize(&mut self) {
            self._data.zeroize();
            self.called.store(true, Ordering::SeqCst);
        }
    }

    let called = Arc::new(AtomicBool::new(false));
    let witness = ZeroizeWitness { called: Arc::clone(&called), _data: vec![0xFFu8; 8] };
    let secret2 = Secret::new(witness);
    drop(secret2);
    assert!(called.load(Ordering::SeqCst), "zeroize() must be called on drop");
}

/// After dropping a `compat::v10::SecretBox<Vec<u8>>`, zeroize was called.
///
/// NOTE: real `secrecy 0.10.1` also zeroizes on drop via `ZeroizeOnDrop`.
/// This test confirms our shim matches that behavior.
#[test]
fn compat_zeroize_on_drop_v10() {
    use secure_gate_compat::compat::v10::SecretBox;

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct ZeroizeWitness {
        called: Arc<AtomicBool>,
        _data: Vec<u8>,
    }
    impl zeroize::Zeroize for ZeroizeWitness {
        fn zeroize(&mut self) {
            self._data.zeroize();
            self.called.store(true, Ordering::SeqCst);
        }
    }

    let called = Arc::new(AtomicBool::new(false));
    let witness = ZeroizeWitness { called: Arc::clone(&called), _data: vec![0xAAu8; 8] };
    let secret = SecretBox::new(Box::new(witness));
    drop(secret);
    assert!(called.load(Ordering::SeqCst), "zeroize() must be called on drop");
}

// ── Section B: Shim-only stricter behaviors ───────────────────────────────────
//
// The tests below document the CORRECT pattern for each restricted behavior.
// The compile-fail counterparts (what you must NOT do) live in tests/compile-fail/.

/// `Deref` is intentionally absent from `compat::v08::Secret`.
///
/// Real secrecy v0.8.0 also does not implement `Deref` — you must call
/// `.expose_secret()`. The shim preserves this restriction, and additionally
/// has a compile-fail test (`compat_no_deref.rs`) that locks it in.
///
/// This test documents the correct idiom.
#[test]
fn compat_v08_no_deref_correct_idiom() {
    use secure_gate_compat::compat::v08::Secret;
    use secure_gate_compat::compat::ExposeSecret;

    let s = Secret::new(String::from("no_deref_value"));
    // CORRECT: use expose_secret() explicitly
    let inner: &String = s.expose_secret();
    assert_eq!(inner, "no_deref_value");
    // WRONG (will not compile): *s or s.len() directly
    // See tests/compile-fail/compat_no_deref.rs
}

/// `AsRef` is intentionally absent from `compat::v08::Secret`.
///
/// Prevents accidental passing of `&str` where `&Secret<String>` is meant.
/// The shim does not implement `AsRef<String>` or `AsRef<str>`.
///
/// This test documents the correct idiom.
#[test]
fn compat_v08_no_asref_correct_idiom() {
    use secure_gate_compat::compat::v08::Secret;
    use secure_gate_compat::compat::ExposeSecret;

    let s = Secret::new(String::from("no_asref_value"));
    // CORRECT: call expose_secret() then use AsRef on the inner value
    let as_str: &str = s.expose_secret().as_str();
    assert_eq!(as_str, "no_asref_value");
    // WRONG (will not compile): some_fn_taking_asref_str(&s)
    // See tests/compile-fail/compat_no_asref.rs
}

/// `Debug` requires `S: DebugSecret` — accidental `{:?}` on an unmarked type fails to compile.
///
/// Real secrecy v0.8.0 has the same requirement: `Debug for Secret<S>` is only
/// impl'd when `S: DebugSecret`. Our shim matches this exactly.
///
/// This test documents the correct idiom: implement `DebugSecret` on your type.
#[test]
fn compat_v08_debug_requires_marker_correct_idiom() {
    use secure_gate_compat::compat::v08::{DebugSecret, Secret};

    // A custom type that opts in to debug display
    struct ApiKey(String);
    impl zeroize::Zeroize for ApiKey {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }
    impl DebugSecret for ApiKey {}

    let key = Secret::new(ApiKey(String::from("sk_live_xyz")));
    let dbg = format!("{:?}", key);
    // Output is redacted — the value never appears
    assert!(!dbg.contains("sk_live_xyz"), "Debug must redact the value: {dbg}");
    assert!(dbg.contains("REDACTED"), "Debug must say REDACTED: {dbg}");
    // WRONG (will not compile): struct Unmarked(String); Secret::new(Unmarked(...))
    // then format!("{:?}", secret) without impl DebugSecret for Unmarked.
    // See tests/compile-fail/compat_no_debug_without_marker.rs
}
