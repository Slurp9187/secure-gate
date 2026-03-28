//! Parity tests for the secrecy v0.10.1 API surface.
//!
//! # Part A — `dual_test_v10!` shared-API tests
//!
//! Each test runs twice: once against `secrecy 0.10.1` (crate alias `secrecy_v10`)
//! and once against `secure_gate_compat::compat::v10`. Bodies are identical; only imports
//! differ (injected by the macro).
//!
//! Source-verified against:
//! - `crates-secrecy-v0.10.1/secrecy/src/lib.rs` (real API)
//! - `src/compat/v10.rs` (shim implementation)
//!
//! ## Real secrecy v0.10.1 does NOT have (shim extensions only — see Part B):
//!
//! - `From<&str> for SecretString` — real secrecy only has `From<String>`
//! - `Default for SecretString` — `str: !Default`, no concrete impl in real secrecy
//! - `Default for SecretSlice<S>` — `[S]: !Default`, no concrete impl in real secrecy
//! - `FromStr for SecretString` — not in real secrecy v0.10.1
//!
//! # Part B — shim-extension tests
//!
//! APIs our shim adds beyond what real secrecy v0.10.1 provides, plus the
//! migration bridge to native `Dynamic<T>` / `with_secret`.
#![allow(unused_doc_comments)]

// ── Part A: dual tests ───────────────────────────────────────────────────────

/// `SecretBox::new(Box::new(val))` — primary constructor with pre-boxed value.
dual_test_v10!(secret_box_new_from_box {
    let sb = SecretBox::new(Box::new(String::from("hunter2")));
    assert_eq!(sb.expose_secret(), "hunter2");
});

/// `Box::new(val).into()` — `From<Box<S>> for SecretBox<S>` exists in both.
dual_test_v10!(secret_box_from_box_into {
    let sb: SecretBox<String> = Box::new(String::from("token")).into();
    assert_eq!(sb.expose_secret(), "token");
});

/// `SecretBox::init_with(|| val)` — closure constructor (for `S: Clone`).
dual_test_v10!(secret_box_init_with {
    let sb = SecretBox::init_with(|| String::from("init_with_value"));
    assert_eq!(sb.expose_secret(), "init_with_value");
});

/// `SecretBox::init_with_mut(|s| ...)` — mutable initializer (for `S: Default`).
dual_test_v10!(secret_box_init_with_mut {
    let sb = SecretBox::<String>::init_with_mut(|s| {
        s.push_str("mutated");
    });
    assert_eq!(sb.expose_secret(), "mutated");
});

/// `SecretBox::try_init_with(|| Ok(val))` — fallible constructor, success case.
dual_test_v10!(secret_box_try_init_with_ok {
    let result: Result<SecretBox<String>, &str> =
        SecretBox::try_init_with(|| Ok(String::from("ok_value")));
    assert_eq!(result.unwrap().expose_secret(), "ok_value");
});

/// `SecretBox::try_init_with(|| Err(...))` — fallible constructor, error case.
dual_test_v10!(secret_box_try_init_with_err {
    let result: Result<SecretBox<String>, &str> =
        SecretBox::try_init_with(|| Err("deliberate_error"));
    assert!(result.is_err());
});

/// `expose_secret()` returns the correct inner value.
dual_test_v10!(secret_box_expose_secret {
    let sb = SecretBox::new(Box::new(vec![1u8, 2, 3]));
    assert_eq!(sb.expose_secret(), &[1u8, 2, 3]);
});

/// `expose_secret_mut()` returns a mutable reference and mutations persist.
dual_test_v10!(secret_box_expose_secret_mut {
    let mut sb = SecretBox::<Vec<u8>>::init_with_mut(|v| v.extend_from_slice(&[10, 20]));
    sb.expose_secret_mut().push(30);
    assert_eq!(sb.expose_secret(), &[10u8, 20, 30]);
});

/// `Debug` output does NOT expose the inner value.
dual_test_v10!(secret_box_debug_redacted {
    let sb = SecretBox::new(Box::new(String::from("hunter2")));
    let dbg = format!("{:?}", sb);
    assert!(!dbg.contains("hunter2"), "Debug must not expose the secret: {dbg}");
});

/// `Debug` format is `SecretBox<typename>([REDACTED])` in both real and shim.
dual_test_v10!(secret_box_debug_format {
    let sb = SecretBox::new(Box::new(String::from("x")));
    let dbg = format!("{:?}", sb);
    assert!(dbg.starts_with("SecretBox<"), "Debug must start with SecretBox<: {dbg}");
    assert!(dbg.contains("[REDACTED]"), "Debug must contain [REDACTED]: {dbg}");
});

/// `SecretString::from(String::from(...))` — `From<String>` exists in both v0.10.1 sources.
dual_test_v10!(secret_string_from_string {
    let ss: SecretString = SecretString::from(String::from("correct_horse"));
    assert_eq!(ss.expose_secret(), "correct_horse");
});

/// `expose_secret()` on a `SecretString` returns a `&str` equal to the original.
dual_test_v10!(secret_string_expose {
    let ss = SecretString::from(String::from("token_abc"));
    let exposed: &str = ss.expose_secret();
    assert_eq!(exposed, "token_abc");
});

/// `Debug` on `SecretString` does not contain the value.
dual_test_v10!(secret_string_debug_redacted {
    let ss = SecretString::from(String::from("my_secret_token"));
    let dbg = format!("{:?}", ss);
    assert!(!dbg.contains("my_secret_token"), "Debug must not expose value: {dbg}");
    assert!(dbg.contains("[REDACTED]"), "Debug must contain [REDACTED]: {dbg}");
});

/// `SecretSlice::from(vec![...])` — `From<Vec<S>>` exists in both v0.10.1 sources.
dual_test_v10!(secret_slice_from_vec {
    let ss: SecretSlice<u8> = SecretSlice::from(vec![0xAAu8, 0xBB, 0xCC]);
    assert_eq!(ss.expose_secret(), &[0xAAu8, 0xBB, 0xCC]);
});

/// Exposed slice content matches the input vector.
dual_test_v10!(secret_slice_expose {
    let data = vec![5u8, 10, 15, 20];
    let ss: SecretSlice<u8> = SecretSlice::from(data);
    assert_eq!(ss.expose_secret().len(), 4);
    assert_eq!(ss.expose_secret()[3], 20);
});

/// `Clone for SecretBox<S: CloneableSecret>` — both real secrecy and shim provide this.
///
/// NOTE: primitives like `u32` are NOT `CloneableSecret` in real secrecy v0.10.1
/// (no built-in blanket impls for primitives). We define a local struct that opts in to
/// `CloneableSecret` in the macro body; the `impl CloneableSecret for Token {}` in each
/// branch targets the appropriate trait (real or compat), making this dual-testable.
dual_test_v10!(cloneable_box_clone_independent {
    #[derive(Clone)]
    struct Token(u32);
    impl zeroize::Zeroize for Token {
        fn zeroize(&mut self) { self.0 = 0; }
    }
    impl CloneableSecret for Token {}

    let sb1 = SecretBox::new(Box::new(Token(42)));
    let sb2 = sb1.clone();
    assert_eq!(sb1.expose_secret().0, sb2.expose_secret().0);
});

/// A generic function accepting `T: ExposeSecret<String>` compiles and runs on both.
dual_test_v10!(generic_fn_expose_secret {
    fn read_secret<T: ExposeSecret<String>>(t: &T) -> usize {
        t.expose_secret().len()
    }
    let sb = SecretBox::new(Box::new(String::from("hello")));
    assert_eq!(read_secret(&sb), 5);
});

/// A generic function accepting `T: ExposeSecretMut<String>` compiles and runs on both.
dual_test_v10!(generic_fn_expose_secret_mut {
    fn append_secret<T: ExposeSecretMut<String>>(t: &mut T, suffix: &str) {
        t.expose_secret_mut().push_str(suffix);
    }
    let mut sb = SecretBox::new(Box::new(String::from("base")));
    append_secret(&mut sb, "_appended");
    assert_eq!(sb.expose_secret(), "base_appended");
});

/// Non-string inner type: `SecretBox<u32>`.
dual_test_v10!(secret_box_u32 {
    let sb = SecretBox::new(Box::new(99u32));
    assert_eq!(*sb.expose_secret(), 99u32);
});

/// A `SecretBox` can be moved into a function and accessed there.
dual_test_v10!(move_into_function_v10 {
    fn consume<T: ExposeSecret<String>>(s: T) -> usize {
        s.expose_secret().len()
    }
    let sb = SecretBox::new(Box::new(String::from("movable")));
    assert_eq!(consume(sb), 7);
});

// ── Part B: shim-extension tests ─────────────────────────────────────────────
//
// These APIs are added by our shim but are NOT present in real secrecy v0.10.1.
// They are ergonomic additions that simplify common use-cases.

/// Our shim adds `From<&'a str> for SecretString`.
/// Real secrecy v0.10.1 only provides `From<String>`.
#[test]
fn compat_v10_string_from_str_ref() {
    use secure_gate_compat::compat::v10::SecretString;
    use secure_gate_compat::compat::ExposeSecret;

    let ss = SecretString::from("from_str_ref");
    assert_eq!(ss.expose_secret(), "from_str_ref");
}

/// Our shim adds `FromStr for SecretString`.
/// Real secrecy v0.10.1 does not implement `FromStr` for `SecretString`.
#[test]
fn compat_v10_string_from_str_parse() {
    use secure_gate_compat::compat::v10::SecretString;
    use secure_gate_compat::compat::ExposeSecret;

    let ss: SecretString = "parse_me".parse().unwrap();
    assert_eq!(ss.expose_secret(), "parse_me");
}

/// Our shim adds `Default for SecretString` (= `SecretBox<str>`).
/// Real secrecy v0.10.1 has no such impl because `str: !Default`.
#[test]
fn compat_v10_string_default() {
    use secure_gate_compat::compat::v10::SecretString;
    use secure_gate_compat::compat::ExposeSecret;

    let ss = SecretString::default();
    assert!(ss.expose_secret().is_empty());
}

/// Our shim adds `Default for SecretSlice<S>` (= `SecretBox<[S]>`), returning an empty slice.
/// Real secrecy v0.10.1 has no such impl because `[S]: !Default`.
#[test]
fn compat_v10_slice_default() {
    use secure_gate_compat::compat::v10::SecretSlice;
    use secure_gate_compat::compat::ExposeSecret;

    let ss = SecretSlice::<u8>::default();
    assert!(ss.expose_secret().is_empty());
}

/// After migrating `SecretBox<String>` → `Dynamic<String>`, `with_secret` reads the value.
///
/// This demonstrates the preferred post-migration access pattern: the native
/// `with_secret` scoped API limits borrow lifetime and is audit-greppable.
#[test]
fn compat_v10_bridge_with_secret() {
    use secure_gate_compat::compat::ExposeSecret as CompatExposeSecret;
    use secure_gate_compat::compat::v10::SecretBox;
    use secure_gate::{Dynamic, RevealSecret};

    let compat = SecretBox::new(Box::new(String::from("migrated")));
    // Verify compat access first
    assert_eq!(compat.expose_secret(), "migrated");

    // Migrate to native type
    let native: Dynamic<String> = compat.into();
    // Native scoped access — RevealSecret must be in scope for with_secret
    let len = RevealSecret::with_secret(&native, |v| v.len());
    assert_eq!(len, 8);
}
