// Integration tests for the secrecy v0.8.0 compatibility layer (compat::v08).
//
// These tests verify:
//   1.  Secret<S> construction via new() and From<S>
//   2.  ExposeSecret — read-only access
//   3.  Debug via DebugSecret (always [REDACTED], never leaks the value)
//   4.  DebugSecret — default and custom impls
//   5.  CloneableSecret — Clone only when the marker is present
//   6.  SecretString (= Secret<String>) — FromStr, From<&str>/From<String>, Clone, Debug
//   7.  SecretVec<T> (= Secret<Vec<T>>) — construction, access
//   8.  SecretBox<S> (= Secret<Box<S>>) — construction, access
//   9.  CloneableSecret for String and Vec (v0.8 additions)
//  10.  Bridge: Dynamic<T> satisfies compat::ExposeSecret
//  11.  Conversion: Secret<String> ↔ Dynamic<String>
//  12.  Conversion: Secret<Vec<T>> ↔ Dynamic<Vec<T>>
//  13.  Conversion: Secret<[T; N]> ↔ Fixed<[T; N]>
//  14.  Serde Deserialize/Serialize (feature-gated)
//  15.  zeroize re-export accessible via compat::zeroize

use secure_gate::compat::v08::{DebugSecret, Secret, SecretBox, SecretString, SecretVec};
use secure_gate::compat::{CloneableSecret, ExposeSecret};
use secure_gate::{Dynamic, Fixed};

// ── 1. Secret<S> construction ────────────────────────────────────────────────

#[test]
fn secret_new() {
    let s: Secret<u32> = Secret::new(42u32);
    assert_eq!(s.expose_secret(), &42u32);
}

#[test]
fn secret_from_trait() {
    let s: Secret<u32> = 42u32.into();
    assert_eq!(s.expose_secret(), &42u32);
}

#[test]
fn secret_from_array() {
    let s: Secret<[u8; 4]> = Secret::new([1, 2, 3, 4]);
    assert_eq!(s.expose_secret(), &[1u8, 2, 3, 4]);
}

// ── 2. ExposeSecret — read-only access ───────────────────────────────────────

#[test]
fn expose_secret_returns_reference() {
    let s: Secret<String> = Secret::new(String::from("hello"));
    let r: &String = s.expose_secret();
    assert_eq!(r, "hello");
}

// ── 3. Debug — always [REDACTED] ─────────────────────────────────────────────

#[test]
fn debug_does_not_leak_value() {
    #[derive(Clone)]
    struct Password(String);

    impl zeroize::Zeroize for Password {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }
    impl DebugSecret for Password {}

    let s = Secret::new(Password(String::from("hunter2")));
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("[REDACTED"), "Debug must contain [REDACTED: {dbg}");
    assert!(!dbg.contains("hunter2"), "Debug must not leak the value: {dbg}");
    assert!(dbg.starts_with("Secret("), "Debug must wrap with Secret(): {dbg}");
}

// ── 4. DebugSecret — default impl ────────────────────────────────────────────

#[test]
fn debug_secret_default_includes_type_name() {
    let s: Secret<String> = Secret::new(String::from("password"));
    let dbg = format!("{:?}", s);
    // Default DebugSecret impl: [REDACTED alloc::string::String]
    assert!(dbg.contains("[REDACTED"), "{dbg}");
    assert!(dbg.contains("String"), "{dbg}");
    assert!(!dbg.contains("password"), "{dbg}");
}

#[test]
fn debug_secret_custom_impl() {
    use core::fmt;

    struct MyKey;
    impl zeroize::Zeroize for MyKey {
        fn zeroize(&mut self) {}
    }
    impl DebugSecret for MyKey {
        fn debug_secret(f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            f.write_str("[REDACTED MyKey]")
        }
    }

    let s = Secret::new(MyKey);
    let dbg = format!("{:?}", s);
    assert_eq!(dbg, "Secret([REDACTED MyKey])");
}

// ── 5. CloneableSecret ────────────────────────────────────────────────────────

#[test]
fn cloneable_secret_array() {
    let s: Secret<[u8; 4]> = Secret::new([0xABu8; 4]);
    let c = s.clone();
    assert_eq!(s.expose_secret(), c.expose_secret());
}

#[test]
fn cloneable_secret_custom_type() {
    #[derive(Clone)]
    struct Key([u8; 16]);

    impl zeroize::Zeroize for Key {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }
    impl CloneableSecret for Key {}

    let s: Secret<Key> = Secret::new(Key([0xFFu8; 16]));
    let c = s.clone();
    assert_eq!(s.expose_secret().0, c.expose_secret().0);
}

// ── 6. SecretString ───────────────────────────────────────────────────────────

#[test]
fn secret_string_from_str_parse() {
    use core::str::FromStr;
    let s = SecretString::from_str("hello").unwrap();
    assert_eq!(s.expose_secret(), "hello");
}

#[test]
fn secret_string_clone() {
    let s: SecretString = Secret::new(String::from("clone_me"));
    let c = s.clone();
    assert_eq!(s.expose_secret(), c.expose_secret());
}

#[test]
fn secret_string_debug_redacted() {
    let s: SecretString = Secret::new(String::from("password"));
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("[REDACTED"), "{dbg}");
    assert!(!dbg.contains("password"), "{dbg}");
}

// ── 7. SecretVec<T> ──────────────────────────────────────────────────────────

#[test]
fn secret_vec_new_and_access() {
    let v: SecretVec<u8> = Secret::new(vec![1u8, 2, 3, 4]);
    assert_eq!(v.expose_secret(), &[1u8, 2, 3, 4]);
}

#[test]
fn secret_vec_clone() {
    let v: SecretVec<u8> = Secret::new(vec![9u8, 8, 7]);
    let c = v.clone();
    assert_eq!(v.expose_secret(), c.expose_secret());
}

// ── 8. SecretBox<S> (= Secret<Box<S>>) ───────────────────────────────────────
//
// In zeroize 1.8+, Box<T>: Zeroize is only provided for slice-like types
// (Box<[Z]> where Z: Zeroize, and Box<str>). The natural v0.8 use-case is
// a heap-allocated byte slice — SecretBox<[u8]> = Secret<Box<[u8]>>.

#[test]
fn secret_box_byte_slice() {
    let data: Box<[u8]> = Box::from(&[1u8, 2, 3, 4][..]);
    let sb: SecretBox<[u8]> = Secret::new(data);
    let inner: &[u8] = sb.expose_secret().as_ref();
    assert_eq!(inner, &[1u8, 2, 3, 4]);
}

// ── 9. CloneableSecret for String and Vec ────────────────────────────────────

#[test]
fn cloneable_string_direct() {
    // String: CloneableSecret comes from v08 module — verify it compiles and works
    fn assert_cloneable<T: CloneableSecret>(_: &T) {}
    let s = String::from("test");
    assert_cloneable(&s);
}

#[test]
fn cloneable_vec_u8() {
    fn assert_cloneable<T: CloneableSecret>(_: &T) {}
    let v: Vec<u8> = vec![1, 2, 3];
    assert_cloneable(&v);
}

// ── 10. Bridge: Dynamic<T> satisfies compat::ExposeSecret ────────────────────

#[test]
fn dynamic_string_bridge() {
    let d: Dynamic<String> = Dynamic::new(String::from("bridge_v08"));
    let val: &String = ExposeSecret::expose_secret(&d);
    assert_eq!(val, "bridge_v08");
}

#[test]
fn dynamic_vec_bridge() {
    let d: Dynamic<Vec<u8>> = Dynamic::new(vec![10u8, 20, 30]);
    let val: &Vec<u8> = ExposeSecret::expose_secret(&d);
    assert_eq!(val, &[10u8, 20, 30]);
}

#[test]
fn fixed_bridge() {
    let f: Fixed<[u8; 3]> = Fixed::new([1, 2, 3]);
    let val: &[u8; 3] = ExposeSecret::expose_secret(&f);
    assert_eq!(val, &[1u8, 2, 3]);
}

// ── 11. Secret<String> ↔ Dynamic<String> conversions ─────────────────────────

#[test]
fn secret_string_to_dynamic() {
    let s: Secret<String> = Secret::new(String::from("migrate_str"));
    let d: Dynamic<String> = s.into();
    assert_eq!(ExposeSecret::expose_secret(&d), "migrate_str");
}

#[test]
fn dynamic_string_to_secret() {
    let d: Dynamic<String> = Dynamic::new(String::from("back_to_v08"));
    let s: Secret<String> = d.into();
    assert_eq!(s.expose_secret(), "back_to_v08");
}

// ── 12. Secret<Vec<T>> ↔ Dynamic<Vec<T>> conversions ─────────────────────────

#[test]
fn secret_vec_to_dynamic() {
    let s: Secret<Vec<u8>> = Secret::new(vec![1u8, 2, 3]);
    let d: Dynamic<Vec<u8>> = s.into();
    assert_eq!(ExposeSecret::expose_secret(&d), &[1u8, 2, 3]);
}

#[test]
fn dynamic_vec_to_secret() {
    let d: Dynamic<Vec<u8>> = Dynamic::new(vec![4u8, 5, 6]);
    let s: Secret<Vec<u8>> = d.into();
    assert_eq!(s.expose_secret(), &[4u8, 5, 6]);
}

// ── 13. Secret<[T; N]> ↔ Fixed<[T; N]> conversions ───────────────────────────

#[test]
fn secret_array_to_fixed() {
    let s: Secret<[u8; 4]> = Secret::new([0xABu8; 4]);
    let f: Fixed<[u8; 4]> = s.into();
    assert_eq!(ExposeSecret::expose_secret(&f), &[0xABu8; 4]);
}

#[test]
fn fixed_to_secret_array() {
    let f: Fixed<[u8; 4]> = Fixed::new([0xCDu8; 4]);
    let s: Secret<[u8; 4]> = f.into();
    assert_eq!(s.expose_secret(), &[0xCDu8; 4]);
}

// ── 14. Serde (feature-gated) ─────────────────────────────────────────────────

#[cfg(feature = "serde-deserialize")]
#[test]
fn secret_deserialize() {
    let json = r#"42"#;
    let s: Secret<u32> = serde_json::from_str(json).expect("deserialize failed");
    assert_eq!(s.expose_secret(), &42u32);
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn secret_string_deserialize() {
    let json = r#""my_v08_password""#;
    let s: SecretString = serde_json::from_str(json).expect("deserialize failed");
    assert_eq!(s.expose_secret(), "my_v08_password");
}

#[cfg(all(feature = "serde-serialize", feature = "serde-deserialize"))]
#[test]
fn secret_serialize_requires_marker() {
    use secure_gate::compat::SerializableSecret;
    use zeroize::Zeroize;

    #[derive(Clone, Zeroize, serde::Serialize, serde::Deserialize)]
    struct ApiToken(String);

    impl SerializableSecret for ApiToken {}

    let token = ApiToken(String::from("tok_v08_abc"));
    let s: Secret<ApiToken> = Secret::new(token);
    let json = serde_json::to_string(&s).expect("serialize failed");
    assert!(json.contains("tok_v08_abc"), "json: {json}");
}

// ── 15. zeroize re-export accessible ─────────────────────────────────────────

#[test]
fn zeroize_reexport_accessible() {
    use secure_gate::compat::zeroize::Zeroize;
    let mut val = vec![1u8, 2, 3];
    val.zeroize();
    assert!(val.iter().all(|&b| b == 0));
}
