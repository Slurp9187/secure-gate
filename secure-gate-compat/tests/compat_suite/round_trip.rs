//! Cross-type conversion round-trip tests (issue_104 §4).
//!
//! Every direction is tested:
//!   v08::Secret<T>  ↔  Dynamic<T>  ↔  v10::SecretBox<T>
//!   v08::Secret<[T;N]>  ↔  Fixed<[T;N]>
//!   v10::SecretString   ↔  Dynamic<String>  ↔  v08::SecretString
//!
//! Value identity is asserted at every hop via `expose_secret()`.
//! Constant-time equality checks are added where the `ct-eq` feature is active.

use secure_gate::compat::v08::{Secret as V08Secret, SecretString as V08SecretString};
use secure_gate::compat::v10::{SecretBox as V10SecretBox, SecretString as V10SecretString};
use secure_gate::compat::{ExposeSecret, ExposeSecretMut};
use secure_gate::{Dynamic, Fixed};

// ── String: v08 → Dynamic → v10 → Dynamic → v08 ─────────────────────────────

#[test]
fn string_full_round_trip_v08_dynamic_v10_dynamic_v08() {
    let original = "full_migration_string";

    let v08: V08Secret<String> = V08Secret::new(String::from(original));
    assert_eq!(v08.expose_secret(), original);

    let native: Dynamic<String> = v08.into();
    assert_eq!(ExposeSecret::expose_secret(&native), original);

    let v10: V10SecretBox<String> = native.into();
    assert_eq!(v10.expose_secret(), original);

    let native2: Dynamic<String> = v10.into();
    assert_eq!(ExposeSecret::expose_secret(&native2), original);

    let v08_back: V08Secret<String> = native2.into();
    assert_eq!(v08_back.expose_secret(), original);
}

// ── String: v10 → Dynamic → v08 ──────────────────────────────────────────────

#[test]
fn string_v10_to_dynamic_to_v08() {
    let original = "v10_first_migration";
    let v10: V10SecretBox<String> = V10SecretBox::init_with(|| String::from(original));
    let native: Dynamic<String> = v10.into();
    let v08: V08Secret<String> = native.into();
    assert_eq!(v08.expose_secret(), original);
}

// ── SecretString aliases: v08 ↔ Dynamic ↔ v10 ────────────────────────────────

#[test]
fn secret_string_alias_round_trip_v08_to_v10() {
    let v08str: V08SecretString = V08Secret::new(String::from("secret_alias_payload"));
    let native: Dynamic<String> = v08str.into();
    let v10str: V10SecretString = native.into();
    assert_eq!(v10str.expose_secret(), "secret_alias_payload");
}

#[test]
fn secret_string_alias_round_trip_v10_to_v08() {
    let v10str: V10SecretString = "v10_alias_payload".into();
    let native: Dynamic<String> = v10str.into();
    let v08str: V08SecretString = native.into();
    assert_eq!(v08str.expose_secret(), "v10_alias_payload");
}

// ── Vec<u8>: v08 → Dynamic → v10 → Dynamic → v08 ────────────────────────────

#[test]
fn vec_full_round_trip() {
    let data = vec![0xDEu8, 0xAD, 0xBE, 0xEF];

    let v08: V08Secret<Vec<u8>> = V08Secret::new(data.clone());
    let native: Dynamic<Vec<u8>> = v08.into();
    assert_eq!(ExposeSecret::expose_secret(&native), &data);

    let v10: V10SecretBox<Vec<u8>> = native.into();
    assert_eq!(v10.expose_secret(), &data);

    let native2: Dynamic<Vec<u8>> = v10.into();
    assert_eq!(ExposeSecret::expose_secret(&native2), &data);

    let v08_back: V08Secret<Vec<u8>> = native2.into();
    assert_eq!(v08_back.expose_secret(), &data);
}

// ── [u8; 32]: v08 ↔ Fixed ────────────────────────────────────────────────────

#[test]
fn array32_v08_to_fixed_and_back() {
    let key = [0xABu8; 32];
    let v08: V08Secret<[u8; 32]> = V08Secret::new(key);
    let fixed: Fixed<[u8; 32]> = v08.into();
    assert_eq!(ExposeSecret::expose_secret(&fixed), &key);
    let v08_back: V08Secret<[u8; 32]> = fixed.into();
    assert_eq!(v08_back.expose_secret(), &key);
}

#[test]
fn array16_fixed_to_v08_and_back() {
    let nonce = [0x42u8; 16];
    let fixed: Fixed<[u8; 16]> = Fixed::new(nonce);
    let v08: V08Secret<[u8; 16]> = fixed.into();
    assert_eq!(v08.expose_secret(), &nonce);
    let fixed_back: Fixed<[u8; 16]> = v08.into();
    assert_eq!(ExposeSecret::expose_secret(&fixed_back), &nonce);
}

// ── Mutable access preserved through native type ──────────────────────────────

#[test]
fn mutable_access_after_conversion_to_dynamic() {
    let v08str: V08SecretString = V08Secret::new(String::from("mutable_base"));
    let mut native: Dynamic<String> = v08str.into();
    ExposeSecretMut::expose_secret_mut(&mut native).push_str("_appended");
    assert_eq!(ExposeSecret::expose_secret(&native), "mutable_base_appended");

    // Convert back — the mutation is preserved
    let v08_final: V08Secret<String> = native.into();
    assert_eq!(v08_final.expose_secret(), "mutable_base_appended");
}

// ── ct_eq checks after each conversion ───────────────────────────────────────

#[cfg(feature = "ct-eq")]
mod ct_eq_checks {
    use super::*;
    use secure_gate::ConstantTimeEq;

    #[test]
    fn ct_eq_preserved_across_string_round_trip() {
        let payload = "ct_eq_round_trip_payload";
        let da: Dynamic<String> = Dynamic::new(String::from(payload));
        let db: Dynamic<String> = Dynamic::new(String::from(payload));
        assert!(da.ct_eq(&db), "ct_eq must hold for identical values");

        // Convert one through the compat layer and back
        let v08: V08Secret<String> = da.into();
        let da_back: Dynamic<String> = v08.into();
        assert!(da_back.ct_eq(&db), "ct_eq must hold after round-trip through v08");
    }

    #[test]
    fn ct_eq_preserved_across_vec_round_trip() {
        let data = vec![0x01u8, 0x02, 0x03, 0x04];
        let da: Dynamic<Vec<u8>> = Dynamic::new(data.clone());
        let db: Dynamic<Vec<u8>> = Dynamic::new(data.clone());
        assert!(da.ct_eq(&db));

        let v10: V10SecretBox<Vec<u8>> = da.into();
        let da_back: Dynamic<Vec<u8>> = v10.into();
        assert!(da_back.ct_eq(&db), "ct_eq must hold after round-trip through v10");
    }

    #[test]
    fn ct_eq_distinguishes_different_values_after_round_trip() {
        let da: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3]);
        let db: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 4]);
        assert!(!da.ct_eq(&db));

        let v10: V10SecretBox<Vec<u8>> = da.into();
        let da_back: Dynamic<Vec<u8>> = v10.into();
        assert!(!da_back.ct_eq(&db), "ct_eq must still distinguish different values");
    }

    #[test]
    fn ct_eq_fixed_round_trip() {
        let key = [0xFFu8; 32];
        let fa: Fixed<[u8; 32]> = Fixed::new(key);
        let fb: Fixed<[u8; 32]> = Fixed::new(key);
        assert!(fa.ct_eq(&fb));

        let v08: V08Secret<[u8; 32]> = fa.into();
        let fa_back: Fixed<[u8; 32]> = v08.into();
        assert!(fa_back.ct_eq(&fb), "ct_eq must hold after Fixed → v08 → Fixed");
    }
}
