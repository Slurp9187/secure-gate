// Integration tests for the secrecy v0.10.1 compatibility layer (compat::v10).
//
// These tests verify:
//   1. SecretBox construction and access — matches secrecy's API exactly
//   2. SecretString and SecretSlice type aliases and their From impls
//   3. ExposeSecret / ExposeSecretMut traits work on SecretBox
//   4. Bridge impls: Dynamic<T> and Fixed<[T; N]> satisfy ExposeSecret
//   5. Conversions between compat types and native secure-gate types
//   6. CloneableSecret marker and Clone impls
//   7. Debug is always [REDACTED]
//   8. zeroize re-export is accessible
//   9. Serde Deserialize/Serialize (behind feature gates)
//  10. Legacy Secret<T> alias compiles with deprecation

#![allow(deprecated)] // for the Secret<T> alias test

use secure_gate::compat::v10::{SecretBox, SecretSlice, SecretString};
use secure_gate::compat::{CloneableSecret, ExposeSecret, ExposeSecretMut};
use secure_gate::{Dynamic, Fixed};

// ── 1. SecretBox construction ─────────────────────────────────────────────────

#[test]
fn secret_box_new_from_box() {
    let sb: SecretBox<String> = SecretBox::new(Box::new(String::from("hunter2")));
    assert_eq!(sb.expose_secret(), "hunter2");
}

#[test]
fn secret_box_from_box_trait() {
    let sb: SecretBox<String> = Box::new(String::from("password")).into();
    assert_eq!(sb.expose_secret(), "password");
}

#[test]
fn secret_box_init_with_mut() {
    let sb: SecretBox<String> = SecretBox::init_with_mut(|s: &mut String| {
        s.push_str("from_mut");
    });
    assert_eq!(sb.expose_secret(), "from_mut");
}

#[test]
fn secret_box_init_with() {
    let sb: SecretBox<String> = SecretBox::init_with(|| String::from("closure"));
    assert_eq!(sb.expose_secret(), "closure");
}

#[test]
fn secret_box_try_init_with_ok() {
    let result: Result<SecretBox<String>, &str> =
        SecretBox::try_init_with(|| Ok(String::from("ok_val")));
    assert_eq!(result.unwrap().expose_secret(), "ok_val");
}

#[test]
fn secret_box_try_init_with_err() {
    let result: Result<SecretBox<String>, &str> =
        SecretBox::try_init_with(|| Err("deliberate error"));
    assert!(result.is_err());
}

#[test]
fn secret_box_default() {
    let sb: SecretBox<String> = SecretBox::default();
    assert_eq!(sb.expose_secret(), "");
}

// ── 2. SecretBox expose_secret_mut ───────────────────────────────────────────

#[test]
fn secret_box_expose_secret_mut() {
    let mut sb: SecretBox<String> = SecretBox::init_with(|| String::from("original"));
    sb.expose_secret_mut().push_str("_modified");
    assert_eq!(sb.expose_secret(), "original_modified");
}

// ── 3. SecretString ───────────────────────────────────────────────────────────

#[test]
fn secret_string_from_string() {
    let s: SecretString = String::from("my_password").into();
    assert_eq!(s.expose_secret(), "my_password");
}

#[test]
fn secret_string_from_str_ref() {
    let s: SecretString = "my_password".into();
    assert_eq!(s.expose_secret(), "my_password");
}

#[test]
fn secret_string_from_str_trait() {
    use core::str::FromStr;
    let s = SecretString::from_str("parsed").unwrap();
    assert_eq!(s.expose_secret(), "parsed");
}

#[test]
fn secret_string_default() {
    let s = SecretString::default();
    assert_eq!(s.expose_secret(), "");
}

#[test]
fn secret_string_clone() {
    let a: SecretString = "clone_me".into();
    let b = a.clone();
    assert_eq!(a.expose_secret(), b.expose_secret());
}

// ── 4. SecretSlice ────────────────────────────────────────────────────────────

#[test]
fn secret_slice_from_vec() {
    let v: Vec<u8> = vec![1, 2, 3, 4];
    let s: SecretSlice<u8> = v.into();
    assert_eq!(s.expose_secret(), &[1u8, 2, 3, 4]);
}

#[test]
fn secret_slice_default() {
    let s: SecretSlice<u8> = SecretSlice::default();
    assert!(s.expose_secret().is_empty());
}

#[test]
fn secret_slice_clone() {
    let a: SecretSlice<u8> = vec![10u8, 20, 30].into();
    let b = a.clone();
    assert_eq!(a.expose_secret(), b.expose_secret());
}

// ── 5. Debug is always [REDACTED] ────────────────────────────────────────────

#[test]
fn secret_box_debug_redacted() {
    let sb: SecretBox<String> = SecretBox::init_with(|| String::from("sensitive"));
    let dbg = format!("{:?}", sb);
    assert!(dbg.contains("[REDACTED]"), "Debug output should contain [REDACTED]: {}", dbg);
    assert!(!dbg.contains("sensitive"), "Debug must not leak the secret");
}

#[test]
fn secret_string_debug_redacted() {
    let s: SecretString = "sensitive".into();
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("sensitive"));
}

// ── 6. CloneableSecret with SecretBox ────────────────────────────────────────

#[test]
fn cloneable_secret_u32() {
    let sb: SecretBox<u32> = SecretBox::new(Box::new(42u32));
    let cloned = sb.clone();
    assert_eq!(sb.expose_secret(), cloned.expose_secret());
}

#[test]
fn cloneable_secret_custom_type() {
    use zeroize::Zeroize;

    #[derive(Clone, Zeroize)]
    struct ApiKey([u8; 16]);

    impl CloneableSecret for ApiKey {}

    let key = ApiKey([0xABu8; 16]);
    let sb: SecretBox<ApiKey> = SecretBox::new(Box::new(key));
    let cloned = sb.clone();
    assert_eq!(sb.expose_secret().0, cloned.expose_secret().0);
}

// ── 7. Bridge: Dynamic satisfies ExposeSecret ─────────────────────────────────

#[test]
fn dynamic_string_satisfies_expose_secret() {
    let d: Dynamic<String> = Dynamic::new(String::from("bridge_test"));
    let val: &String = ExposeSecret::expose_secret(&d);
    assert_eq!(val, "bridge_test");
}

#[test]
fn dynamic_string_satisfies_expose_secret_mut() {
    let mut d: Dynamic<String> = Dynamic::new(String::from("bridge"));
    ExposeSecretMut::expose_secret_mut(&mut d).push_str("_extended");
    assert_eq!(ExposeSecret::expose_secret(&d), "bridge_extended");
}

#[test]
fn dynamic_vec_satisfies_expose_secret() {
    let d: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3]);
    let val: &Vec<u8> = ExposeSecret::expose_secret(&d);
    assert_eq!(val, &[1u8, 2, 3]);
}

#[test]
fn dynamic_vec_satisfies_expose_secret_mut() {
    let mut d: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2]);
    ExposeSecretMut::expose_secret_mut(&mut d).push(3);
    assert_eq!(ExposeSecret::expose_secret(&d), &[1u8, 2, 3]);
}

// ── 8. Bridge: Fixed satisfies ExposeSecret ───────────────────────────────────

#[test]
fn fixed_satisfies_expose_secret() {
    let f: Fixed<[u8; 4]> = Fixed::new([1, 2, 3, 4]);
    let val: &[u8; 4] = ExposeSecret::expose_secret(&f);
    assert_eq!(val, &[1u8, 2, 3, 4]);
}

#[test]
fn fixed_satisfies_expose_secret_mut() {
    let mut f: Fixed<[u8; 4]> = Fixed::new([0u8; 4]);
    ExposeSecretMut::expose_secret_mut(&mut f)[0] = 99;
    assert_eq!(ExposeSecret::expose_secret(&f)[0], 99);
}

// ── 9. Generic code works with both compat and native types ───────────────────

fn check_secret<T: ExposeSecret<String>>(t: &T, expected: &str) {
    assert_eq!(t.expose_secret(), expected);
}

#[test]
fn generic_expose_secret_with_secret_box() {
    let sb: SecretBox<String> = SecretBox::init_with(|| String::from("generic_test"));
    check_secret(&sb, "generic_test");
}

#[test]
fn generic_expose_secret_with_dynamic() {
    let d: Dynamic<String> = Dynamic::new(String::from("generic_dynamic"));
    check_secret(&d, "generic_dynamic");
}

// ── 10. Conversions: SecretBox → Dynamic ─────────────────────────────────────

#[test]
fn secret_box_string_to_dynamic() {
    let sb: SecretBox<String> = SecretBox::init_with(|| String::from("migrate_me"));
    let native: Dynamic<String> = sb.into();
    assert_eq!(ExposeSecret::expose_secret(&native), "migrate_me");
}

#[test]
fn secret_box_vec_to_dynamic() {
    let sb: SecretBox<Vec<u8>> = SecretBox::new(Box::new(vec![10u8, 20, 30]));
    let native: Dynamic<Vec<u8>> = sb.into();
    assert_eq!(ExposeSecret::expose_secret(&native), &[10u8, 20, 30]);
}

#[test]
fn secret_box_u32_to_dynamic() {
    let sb: SecretBox<u32> = SecretBox::new(Box::new(42u32));
    let native: Dynamic<u32> = sb.into();
    // Dynamic<u32> doesn't implement RevealSecret, but the type is constructed
    // — just verify it was created without panicking
    drop(native);
}

// ── 11. Conversions: Dynamic → SecretBox ─────────────────────────────────────

#[test]
fn dynamic_string_to_secret_box_string() {
    let d: Dynamic<String> = Dynamic::new(String::from("back_compat"));
    let sb: SecretBox<String> = d.into();
    assert_eq!(sb.expose_secret(), "back_compat");
}

#[test]
fn dynamic_string_to_secret_string() {
    let d: Dynamic<String> = Dynamic::new(String::from("to_secret_string"));
    let ss: SecretString = d.into();
    assert_eq!(ss.expose_secret(), "to_secret_string");
}

#[test]
fn secret_string_to_dynamic_string() {
    let ss: SecretString = "from_compat".into();
    let d: Dynamic<String> = ss.into();
    assert_eq!(ExposeSecret::expose_secret(&d), "from_compat");
}

#[test]
fn dynamic_vec_to_secret_box_vec() {
    let d: Dynamic<Vec<u8>> = Dynamic::new(vec![5u8, 6, 7]);
    let sb: SecretBox<Vec<u8>> = d.into();
    assert_eq!(sb.expose_secret(), &[5u8, 6, 7]);
}

// ── 12. zeroize re-export ─────────────────────────────────────────────────────

#[test]
fn zeroize_reexport_accessible() {
    use secure_gate::compat::zeroize::Zeroize;
    let mut val = vec![1u8, 2, 3];
    val.zeroize();
    assert!(val.iter().all(|&b| b == 0));
}

// ── 13. Deprecated Secret<T> alias compiles ───────────────────────────────────

#[test]
fn legacy_secret_alias_compiles() {
    use secure_gate::compat::v10::Secret;
    let _s: Secret<String> = Secret::new(Box::new(String::from("legacy")));
}

// ── 14. Serde (feature-gated) ─────────────────────────────────────────────────

#[cfg(feature = "serde-deserialize")]
#[test]
fn secret_box_deserialize_string() {
    let json = r#""my_secret_password""#;
    let sb: SecretBox<String> = serde_json::from_str(json).expect("deserialize failed");
    assert_eq!(sb.expose_secret(), "my_secret_password");
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn secret_string_deserialize() {
    let json = r#""secret_str""#;
    let ss: SecretString = serde_json::from_str(json).expect("deserialize failed");
    assert_eq!(ss.expose_secret(), "secret_str");
}

#[cfg(all(feature = "serde-serialize", feature = "serde-deserialize"))]
#[test]
fn secret_box_serialize_requires_marker() {
    use secure_gate::compat::SerializableSecret;
    use zeroize::Zeroize;

    #[derive(Clone, Zeroize, serde::Serialize, serde::Deserialize)]
    struct ApiToken(String);

    impl SerializableSecret for ApiToken {}

    let token = ApiToken(String::from("tok_abc123"));
    let sb: SecretBox<ApiToken> = SecretBox::new(Box::new(token));
    let json = serde_json::to_string(&sb).expect("serialize failed");
    assert!(json.contains("tok_abc123"));
}
