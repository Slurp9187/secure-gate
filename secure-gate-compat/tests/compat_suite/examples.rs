//! Canonical migration examples — the copy-paste guide (issue_104 §9).
//!
//! Every function in this module demonstrates a specific migration pattern.
//! The function body is the exact code a user would paste after reading the
//! migration guide. Comments are written from the user's perspective.
//!
//! These examples are referenced from `MIGRATING_FROM_SECRECY.md`.

use secure_gate_compat::compat::v08::{DebugSecret, Secret as V08Secret, SecretString as V08SecretString};
use secure_gate_compat::compat::v10::{SecretBox, SecretSlice, SecretString as V10SecretString};
use secure_gate_compat::compat::{CloneableSecret, ExposeSecret, ExposeSecretMut};
use secure_gate::{Dynamic, Fixed, RevealSecret};

// ── Step 1: Mechanical import swap (v0.8 → secure-gate) ──────────────────────
//
// Before (secrecy 0.8):
//   use secrecy::{Secret, SecretString, ExposeSecret, CloneableSecret};
//
// After (one global find/replace):
//   use secure_gate_compat::compat::v08::{Secret, SecretString};
//   use secure_gate_compat::compat::{ExposeSecret, CloneableSecret};

#[test]
fn ex_v08_import_swap_secret() {
    // Existing code — unchanged except the use statement above.
    let api_key: V08Secret<String> = V08Secret::new(String::from("sk_live_abc123"));
    let key_str: &String = api_key.expose_secret();
    assert!(!key_str.is_empty());
}

// ── Step 1: Mechanical import swap (v0.10 → secure-gate) ─────────────────────
//
// Before (secrecy 0.10):
//   use secrecy::{SecretBox, SecretString, ExposeSecret, ExposeSecretMut};
//
// After:
//   use secure_gate_compat::compat::v10::{SecretBox, SecretString};
//   use secure_gate_compat::compat::{ExposeSecret, ExposeSecretMut};

#[test]
fn ex_v10_import_swap_secret_box() {
    let token: SecretBox<String> = SecretBox::init_with(|| String::from("bearer_token"));
    let t: &String = token.expose_secret();
    assert!(!t.is_empty());
}

// ── Step 2: Read-only access (both versions) ──────────────────────────────────
//
// `expose_secret()` is the escape hatch. Prefer `with_secret` on native types
// once you are fully migrated — it keeps the borrow scoped.

#[test]
fn ex_read_only_access_v08() {
    let password: V08SecretString = V08Secret::new(String::from("hunter2"));

    // Auditable: every callsite with expose_secret is visible to a reviewer.
    let hash_input: &str = password.expose_secret().as_str();
    assert_eq!(hash_input, "hunter2");
}

#[test]
fn ex_read_only_access_v10() {
    let jwt: SecretBox<String> = SecretBox::init_with(|| String::from("eyJhbGci..."));
    let header: &str = jwt.expose_secret().as_str();
    assert!(header.starts_with("eyJ"));
}

// ── Step 3: Mutable access (v0.10 only) ──────────────────────────────────────
//
// secrecy 0.10 added `ExposeSecretMut`. If your code uses it, the compat layer
// provides it identically.

#[test]
fn ex_mutable_access_v10() {
    let mut buffer: SecretBox<Vec<u8>> = SecretBox::init_with(|| vec![0u8; 16]);

    // Fill the buffer with key material (simulated).
    for (i, byte) in buffer.expose_secret_mut().iter_mut().enumerate() {
        *byte = i as u8;
    }

    let key_bytes: &[u8] = buffer.expose_secret();
    assert_eq!(key_bytes[0], 0);
    assert_eq!(key_bytes[15], 15);
}

// ── Step 4: Migrate Secret<String> → Dynamic<String> ─────────────────────────
//
// The From/Into conversions make this a one-liner. The v08 secret is consumed
// and zeroized; the native Dynamic<String> takes ownership.

#[test]
fn ex_migrate_v08_string_to_dynamic() {
    // Old code: Secret<String>
    let old_secret: V08SecretString = V08Secret::new(String::from("migrate_me"));

    // Migration: one .into() call
    let native: Dynamic<String> = old_secret.into();

    // New code: use native API
    let val = native.with_secret(|s| s.clone());
    assert_eq!(val, "migrate_me");
}

// ── Step 5: Migrate Secret<Vec<u8>> → Dynamic<Vec<u8>> ───────────────────────

#[test]
fn ex_migrate_v08_vec_to_dynamic() {
    let old_key: V08Secret<Vec<u8>> = V08Secret::new(vec![0xABu8; 32]);
    let native: Dynamic<Vec<u8>> = old_key.into();
    let len = native.with_secret(|v| v.len());
    assert_eq!(len, 32);
}

// ── Step 6: Migrate Secret<[T; N]> → Fixed<[T; N]> ───────────────────────────
//
// Fixed is the zero-overhead stack-allocated replacement for Secret<[T; N]>.

#[test]
fn ex_migrate_v08_array_to_fixed() {
    let old_key: V08Secret<[u8; 32]> = V08Secret::new([0x42u8; 32]);
    let fixed: Fixed<[u8; 32]> = old_key.into();

    // Fixed has len() / is_empty() without expose_secret
    assert_eq!(fixed.len(), 32);
    assert!(!fixed.is_empty());

    // Explicit access
    let first_byte = fixed.with_secret(|arr| arr[0]);
    assert_eq!(first_byte, 0x42);
}

// ── Step 7: Migrate SecretBox<String> → Dynamic<String> ──────────────────────

#[test]
fn ex_migrate_v10_secret_box_to_dynamic() {
    let old: SecretBox<String> = SecretBox::init_with(|| String::from("v10_payload"));
    let native: Dynamic<String> = old.into();
    let val = native.with_secret(|s| s.clone());
    assert_eq!(val, "v10_payload");
}

// ── Step 8: Write generic code that works with both compat and native ─────────
//
// If you have a library that accepts secrets via trait, the compat traits allow
// a smooth transition: existing callers pass compat types, new code passes native.

fn process_token<T: ExposeSecret<String>>(token: &T) -> usize {
    token.expose_secret().len()
}

#[test]
fn ex_generic_accepts_both_compat_and_native() {
    let compat: SecretBox<String> = SecretBox::init_with(|| String::from("compat_token"));
    let native: Dynamic<String> = Dynamic::new(String::from("native_token"));

    assert_eq!(process_token(&compat), 12);
    assert_eq!(process_token(&native), 12);
}

// ── Step 9: CloneableSecret — opt-in cloning ──────────────────────────────────
//
// Cloning is deliberately opt-in. Implement CloneableSecret on your type to
// enable Clone on the secret wrapper.

#[test]
fn ex_cloneable_secret_opt_in() {
    #[derive(Clone)]
    struct DatabasePassword(String);

    impl zeroize::Zeroize for DatabasePassword {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }
    impl CloneableSecret for DatabasePassword {}

    let primary: V08Secret<DatabasePassword> =
        V08Secret::new(DatabasePassword(String::from("pg_pass_abc")));

    // Clone for a secondary connection pool.
    let replica = primary.clone();
    assert_eq!(primary.expose_secret().0, replica.expose_secret().0);
}

// ── Step 10: DebugSecret — safe logging / tracing ─────────────────────────────
//
// Implement DebugSecret to get `{:?}` support without leaking the value.
// Default impl prints `[REDACTED typename]`.

#[test]
fn ex_debug_secret_safe_logging() {
    struct ApiKey(String);
    impl zeroize::Zeroize for ApiKey {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }
    impl DebugSecret for ApiKey {}

    let key = V08Secret::new(ApiKey(String::from("sk_live_secret")));

    // This is safe to pass to a logger / span.
    let log_output = format!("{:?}", key);
    assert!(!log_output.contains("sk_live_secret"));
    assert!(log_output.contains("[REDACTED"));
}

// ── Step 11: zeroize re-export matches secrecy's ─────────────────────────────
//
// secrecy re-exports `pub use zeroize;`. The compat layer mirrors this exactly,
// so `use secrecy::zeroize::Zeroize;` becomes:
//   `use secure_gate_compat::compat::zeroize::Zeroize;`

#[test]
fn ex_zeroize_reexport_drop_in() {
    use secure_gate_compat::compat::zeroize::Zeroize;

    let mut scratch_buffer: Vec<u8> = vec![0xFFu8; 64];
    scratch_buffer.zeroize();
    assert!(scratch_buffer.iter().all(|&b| b == 0));
}

// ── Step 12: SecretString v10 migrations ─────────────────────────────────────
//
// secrecy 0.10's SecretString = SecretBox<str> (backed by Box<str>, not String).
// The compat layer reproduces this type exactly.

#[test]
fn ex_v10_secret_string_from_multiple_sources() {
    // From &str
    let a: V10SecretString = "from_str_ref".into();
    assert_eq!(a.expose_secret(), "from_str_ref");

    // From String (avoids extra allocation if you have ownership)
    let b: V10SecretString = String::from("from_string").into();
    assert_eq!(b.expose_secret(), "from_string");

    // Default
    let c = V10SecretString::default();
    assert_eq!(c.expose_secret(), "");
}

// ── Step 13: SecretSlice for byte buffers ────────────────────────────────────

#[test]
fn ex_secret_slice_for_byte_buffers() {
    // Typical use: a cryptographic key read from disk
    let raw_key_bytes: Vec<u8> = vec![0x01u8; 32];
    let key: SecretSlice<u8> = raw_key_bytes.into();

    let key_len = key.expose_secret().len();
    assert_eq!(key_len, 32);
}

// ── Step 14: Final step — remove secrecy-compat feature ──────────────────────
//
// Once all types are migrated to Dynamic<T> / Fixed<[T;N]>, remove the
// `secrecy-compat` feature from Cargo.toml. The compiler will flag any
// remaining compat imports. The with_secret / with_secret_mut API is
// available on all native types.

#[test]
fn ex_fully_native_api() {
    // No compat imports — pure secure-gate native API.
    let key: Fixed<[u8; 32]> = Fixed::new([0xABu8; 32]);
    let password: Dynamic<String> = Dynamic::new(String::from("correct_horse_battery_staple"));

    // Scoped access — preferred over expose_secret() in new code.
    let first_byte = key.with_secret(|arr| arr[0]);
    let pass_len = password.with_secret(|s| s.len());

    assert_eq!(first_byte, 0xAB);
    assert_eq!(pass_len, "correct_horse_battery_staple".len());
}
