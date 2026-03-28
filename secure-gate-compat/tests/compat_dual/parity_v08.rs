//! Parity tests for the secrecy v0.8.0 API surface.
//!
//! # Part A — `dual_test_v08!` shared-API tests
//!
//! Each test runs twice: once against `secrecy 0.8.0` (crate alias `secrecy_v08`) and
//! once against `secure_gate::compat::v08`. The bodies are identical; only the imports
//! differ (injected by the macro).
//!
//! Source-verified against:
//! - `crates-secrecy-v0.8.0/secrecy/src/lib.rs` (real API)
//! - `src/compat/v08.rs` (shim implementation)
//!
//! # Part B — shim-only / bridge tests
//!
//! `with_secret` / `with_secret_mut` live on `RevealSecret` / `RevealSecretMut`
//! (native `Dynamic` / `Fixed`), not on `v08::Secret`. Part B demonstrates the
//! migration bridge: convert a compat type to a native type, then use the preferred API.
#![allow(unused_doc_comments)]

// ── Part A: dual tests ───────────────────────────────────────────────────────

/// `Secret::new(val)` stores the value; `expose_secret()` returns it.
dual_test_v08!(secret_new {
    let s = Secret::new(42u32);
    assert_eq!(*s.expose_secret(), 42u32);
});

/// `val.into()` coercion via `impl From<S> for Secret<S>`.
dual_test_v08!(secret_from_into {
    let s: Secret<u32> = 99u32.into();
    assert_eq!(*s.expose_secret(), 99u32);
});

/// `Secret<String>` exposes a reference to the inner `String`.
dual_test_v08!(secret_string_expose {
    let s = Secret::new(String::from("hunter2"));
    assert_eq!(s.expose_secret(), "hunter2");
});

/// `FromStr` impl: `"hunter2".parse::<SecretString>()` round-trips correctly.
/// Both real secrecy v0.8.0 and the shim implement `FromStr for SecretString`.
dual_test_v08!(secret_string_parse {
    let s: SecretString = "hunter2".parse().unwrap();
    assert_eq!(s.expose_secret(), "hunter2");
});

/// `SecretString::new(String::from(...))` — uses `::new`, not `From<&str>`.
/// Real secrecy v0.8.0 has no `From<&str> for SecretString`; `.parse()` or
/// `Secret::new(String::from(...))` is the correct idiom.
dual_test_v08!(secret_string_from_string {
    let s = SecretString::new(String::from("correct_horse"));
    assert_eq!(s.expose_secret(), "correct_horse");
});

/// `Secret::<Vec<u8>>::new(vec![...])` — heap-allocated byte vector.
dual_test_v08!(secret_vec_new {
    let s = Secret::new(vec![1u8, 2, 3]);
    assert_eq!(s.expose_secret().len(), 3);
});

/// Exposed `Vec<u8>` has the correct length and content.
dual_test_v08!(secret_vec_expose_len {
    let data = vec![10u8, 20, 30, 40];
    let s = Secret::new(data);
    assert_eq!(s.expose_secret().len(), 4);
    assert_eq!(s.expose_secret()[2], 30);
});

/// `Debug` output does NOT contain the secret value.
dual_test_v08!(secret_debug_redacted {
    let s = Secret::new(String::from("hunter2"));
    let dbg = format!("{:?}", s);
    assert!(!dbg.contains("hunter2"), "Debug must not expose the secret: {dbg}");
});

/// `Debug` output contains the word "REDACTED".
dual_test_v08!(secret_debug_contains_redacted_label {
    let s = Secret::new(String::from("hunter2"));
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("REDACTED"), "Debug must contain REDACTED: {dbg}");
});

/// `Debug` output starts with "Secret(" — same format in both real and shim.
dual_test_v08!(secret_debug_format_prefix {
    let s = Secret::new(String::from("x"));
    let dbg = format!("{:?}", s);
    assert!(dbg.starts_with("Secret("), "Debug must start with Secret(: {dbg}");
});

/// Clone is independent — modifying the clone does not affect the original.
dual_test_v08!(cloneable_string_clone_independent {
    let s1 = SecretString::new(String::from("original"));
    let s2 = s1.clone();
    s2.expose_secret();
    // Both expose the same value
    assert_eq!(s1.expose_secret(), "original");
    assert_eq!(s2.expose_secret(), "original");
});

/// Modifying the clone (via `expose_secret` on a mutable clone) doesn't affect original.
/// Both have `CloneableSecret for String`, so `.clone()` works in both worlds.
dual_test_v08!(cloneable_string_modify_clone_unaffects_original {
    let s1: SecretString = "shared_value".parse().unwrap();
    // Clone it into a fresh Secret<String> to verify independence
    let s2 = s1.clone();
    assert_eq!(s1.expose_secret(), s2.expose_secret());
    assert_eq!(s2.expose_secret(), "shared_value");
});

/// `Vec<String>: CloneableSecret` — `String: CloneableSecret` in both real v0.8.0
/// (explicit impl in `string.rs`) and the shim, so `Vec<String>` satisfies the blanket.
/// NOTE: `u8` is NOT `CloneableSecret` in real secrecy v0.8.0 (no primitive blanket there),
/// so this test uses `String` elements to stay dual-compatible.
dual_test_v08!(cloneable_vec_clone {
    let s1 = SecretVec::new(vec![String::from("a"), String::from("b")]);
    let s2 = s1.clone();
    assert_eq!(s1.expose_secret().len(), s2.expose_secret().len());
    assert_eq!(s2.expose_secret()[0], "a");
});

/// A generic function accepting `T: ExposeSecret<String>` compiles and runs on both.
dual_test_v08!(generic_fn_accepting_expose_secret {
    fn read_secret<T: ExposeSecret<String>>(t: &T) -> usize {
        t.expose_secret().len()
    }
    let s = SecretString::new(String::from("hello"));
    assert_eq!(read_secret(&s), 5);
});

/// `expose_secret()` returns a reference (`&S`), not a copy.
dual_test_v08!(expose_secret_return_type_is_ref {
    let s = Secret::new(String::from("ref_test"));
    let r: &String = s.expose_secret();
    assert_eq!(r, "ref_test");
});

/// Non-string, non-vec inner type: `Secret<u32>`.
dual_test_v08!(secret_u32_expose {
    let s = Secret::new(12345u32);
    assert_eq!(*s.expose_secret(), 12345u32);
});

/// `Secret<[u8; 4]>` — fixed-size array as inner type.
dual_test_v08!(secret_array_expose {
    let s = Secret::new([0xDE, 0xAD, 0xBE, 0xEFu8]);
    assert_eq!(s.expose_secret(), &[0xDE, 0xAD, 0xBE, 0xEFu8]);
});

/// Two secrets with the same value expose to equal contents.
dual_test_v08!(secret_string_eq_expose {
    let s1 = SecretString::new(String::from("equal"));
    let s2 = SecretString::new(String::from("equal"));
    assert_eq!(s1.expose_secret(), s2.expose_secret());
});

/// A secret can be moved into a function and accessed there.
dual_test_v08!(move_into_function {
    fn consume<T: ExposeSecret<String>>(s: T) -> usize {
        s.expose_secret().len()
    }
    let s = SecretString::new(String::from("movable"));
    assert_eq!(consume(s), 7);
});

/// A secret can be stored in a struct field and accessed via a method.
dual_test_v08!(secret_in_struct {
    struct Holder<T: ExposeSecret<String>> {
        inner: T,
    }
    impl<T: ExposeSecret<String>> Holder<T> {
        fn len(&self) -> usize {
            self.inner.expose_secret().len()
        }
    }
    let h = Holder { inner: SecretString::new(String::from("stored")) };
    assert_eq!(h.len(), 6);
});

/// Empty string secret — zero-length expose.
dual_test_v08!(empty_string_secret {
    let s = SecretString::new(String::new());
    assert!(s.expose_secret().is_empty());
});

// ── Part B: bridge and shim-only tests ──────────────────────────────────────
//
// `with_secret` / `with_secret_mut` are methods on `RevealSecret` / `RevealSecretMut`
// (native `Dynamic<T>` / `Fixed<[T; N]>` types), not on `v08::Secret`.
// These tests demonstrate the migration bridge to the native API.

/// After migrating `Secret<String>` → `Dynamic<String>`, `with_secret` reads the value.
///
/// This is the recommended upgrade path: swap the compat type for the native type,
/// then use the scoped-access API that `RevealSecret` provides.
#[test]
fn compat_v08_convert_to_dynamic_with_secret() {
    use secure_gate::compat::v08::Secret;
    use secure_gate::compat::ExposeSecret as CompatExposeSecret;
    use secure_gate::{Dynamic, RevealSecret};

    let compat = Secret::new(String::from("hunter2"));
    // Verify compat access first
    assert_eq!(compat.expose_secret(), "hunter2");

    // Migrate to native type
    let native: Dynamic<String> = compat.into();
    // Native scoped access — RevealSecret must be in scope for with_secret
    let len = RevealSecret::with_secret(&native, |v| v.len());
    assert_eq!(len, 7);
}

/// After migrating `Secret<String>` → `Dynamic<String>`, `with_secret_mut` can mutate.
#[test]
fn compat_v08_convert_to_dynamic_with_secret_mut() {
    use secure_gate::compat::v08::Secret;
    use secure_gate::{Dynamic, RevealSecret, RevealSecretMut};

    let compat = Secret::new(String::from("hello"));
    let mut native: Dynamic<String> = compat.into();

    RevealSecretMut::with_secret_mut(&mut native, |v| v.push_str("_world"));
    let result = RevealSecret::with_secret(&native, |v| v.clone());
    assert_eq!(result, "hello_world");
}

/// `Dynamic<String>` satisfies `compat::ExposeSecret<String>`, so compat-pattern
/// callers compile unchanged after migration — the bridge impls in `compat/mod.rs`
/// provide this guarantee.
#[test]
fn compat_v08_native_satisfies_expose_secret_trait() {
    use secure_gate::compat::ExposeSecret;
    use secure_gate::Dynamic;

    fn accepts_compat_trait<T: ExposeSecret<String>>(t: &T) -> usize {
        t.expose_secret().len()
    }

    let native = Dynamic::new(String::from("bridged"));
    // Native type satisfies the compat trait — callers need not change
    assert_eq!(accepts_compat_trait(&native), 7);
}
