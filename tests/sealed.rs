//! Public behavior of the `sealed` feature: round trips, mutation, comparison, cloning,
//! redaction, pre-key lifetime, and sealed `fixed_newtype!` roles.
#![cfg(feature = "sealed")]

use std::sync::Arc;

use secure_gate::{
    Dynamic, Fixed, Prekey, RevealSecret, SealedDynamic, SealedFixed, fixed_newtype,
    sealed_fixed_newtype,
};

fixed_newtype!(pub AppKey, 32, "The app key.");
fixed_newtype!(pub DbKey, 32, "A database key.");
sealed_fixed_newtype!(pub SealedAppKey, AppKey, "The app key, sealed.");
sealed_fixed_newtype!(pub SealedDbKey, DbKey);

#[test]
fn sealed_fixed_round_trips() {
    let prekey = Prekey::new();
    let s = SealedFixed::seal(Fixed::new([0xA5u8; 32]), &prekey);
    assert_eq!(s.len(), 32);
    assert!(!s.is_empty());
    s.with_secret(|b| assert_eq!(b, &[0xA5u8; 32]));
    s.with_secret(|b| assert_eq!(b, &[0xA5u8; 32]));
    let plain = s.unseal();
    plain.with_secret(|b| assert_eq!(b, &[0xA5u8; 32]));
}

#[test]
fn sealed_fixed_with_secret_mut_persists_the_change() {
    let prekey = Prekey::new();
    let mut s = SealedFixed::seal(Fixed::new([0u8; 4]), &prekey);
    let r = s.with_secret_mut(|b| {
        b[2] = 9;
        "returned"
    });
    assert_eq!(r, "returned");
    s.with_secret(|b| assert_eq!(b, &[0, 0, 9, 0]));
}

#[test]
fn a_panic_inside_with_secret_mut_leaves_the_sealed_value_unchanged() {
    let prekey = Prekey::new();
    let mut s = SealedFixed::seal(Fixed::new([1u8; 4]), &prekey);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.with_secret_mut(|b| {
            b[0] = 2;
            panic!("closure failed");
        })
    }));
    assert!(result.is_err());
    s.with_secret(|b| assert_eq!(b, &[1u8; 4]));
}

#[test]
fn sealed_fixed_from_random_is_random() {
    let prekey = Prekey::new();
    let a = SealedFixed::<32>::from_random(&prekey);
    let b = SealedFixed::<32>::from_random(&prekey);
    let (a, b) = (a.unseal(), b.unseal());
    assert_ne!(a.expose_secret(), b.expose_secret());
}

#[test]
fn sealed_dynamic_vec_round_trips_including_empty() {
    let prekey = Prekey::new();
    for len in [0usize, 1, 31, 4096] {
        let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let s = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(data.clone()), &prekey);
        assert_eq!(s.len(), len);
        assert_eq!(s.is_empty(), len == 0);
        s.with_secret(|v: &Vec<u8>| assert_eq!(v, &data));
        let plain = s.unseal();
        plain.with_secret(|v| assert_eq!(v, &data));
    }
}

#[test]
fn sealed_dynamic_string_round_trips_and_mutates_in_place() {
    let prekey = Prekey::new();
    let mut s = SealedDynamic::seal(Dynamic::<String>::new(String::from("pässwörd")), &prekey);
    assert_eq!(s.len(), "pässwörd".len());
    s.with_secret_mut(|p: &mut str| p.make_ascii_uppercase());
    s.with_secret(|p: &String| assert_eq!(p, "PäSSWöRD"));
    let plain: Dynamic<String> = s.unseal();
    plain.with_secret(|p| assert_eq!(p, "PäSSWöRD"));
}

#[test]
fn sealed_dynamic_vec_mutates_in_place() {
    let prekey = Prekey::new();
    let mut s = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(vec![1, 2, 3]), &prekey);
    s.with_secret_mut(|b: &mut [u8]| b.reverse());
    s.with_secret(|v| assert_eq!(v, &vec![3, 2, 1]));
}

#[cfg(feature = "ct-eq")]
#[test]
fn ct_eq_compares_plaintext_across_salts_and_prekeys() {
    use secure_gate::ConstantTimeEq;
    let (p1, p2) = (Prekey::new(), Prekey::new());
    let a = SealedFixed::seal(Fixed::new([3u8; 32]), &p1);
    let b = SealedFixed::seal(Fixed::new([3u8; 32]), &p2);
    let c = SealedFixed::seal(Fixed::new([4u8; 32]), &p1);
    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));

    let d = SealedDynamic::seal(Dynamic::<String>::new(String::from("same")), &p1);
    let e = SealedDynamic::seal(Dynamic::<String>::new(String::from("same")), &p2);
    let f = SealedDynamic::seal(Dynamic::<String>::new(String::from("sam")), &p1);
    let g = SealedDynamic::seal(Dynamic::<String>::new(String::from("sane")), &p1);
    assert!(d.ct_eq(&e));
    assert!(!d.ct_eq(&f));
    assert!(!d.ct_eq(&g));

    let k1 = SealedAppKey::seal(AppKey::new([5u8; 32]), &p1);
    let k2 = SealedAppKey::seal(AppKey::new([5u8; 32]), &p2);
    let k3 = SealedAppKey::seal(AppKey::new([6u8; 32]), &p2);
    assert!(k1.ct_eq(&k2));
    assert!(!k1.ct_eq(&k3));
}

#[test]
fn debug_reveals_nothing() {
    let prekey = Prekey::new();
    let f = SealedFixed::seal(Fixed::new([1u8; 32]), &prekey);
    let d = SealedDynamic::seal(Dynamic::<String>::new(String::from("hunter2")), &prekey);
    let k = SealedAppKey::seal(AppKey::new([1u8; 32]), &prekey);
    for s in [
        format!("{f:?}"),
        format!("{d:?}"),
        format!("{k:?}"),
        format!("{prekey:?}"),
    ] {
        assert_eq!(s, "[REDACTED]");
    }
}

#[test]
fn the_prekey_lives_exactly_as_long_as_its_last_reference() {
    let prekey = Prekey::new();
    let weak = Arc::downgrade(&prekey);
    let a = SealedFixed::seal(Fixed::new([1u8; 32]), &prekey);
    let b = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(vec![1]), &prekey);
    drop(prekey);
    assert!(
        weak.upgrade().is_some(),
        "sealed objects keep the pre-key alive"
    );
    a.with_secret(|_| ());
    drop(a);
    assert!(weak.upgrade().is_some());
    drop(b);
    assert!(weak.upgrade().is_none(), "the last drop frees the pre-key");
}

// Whether a lock succeeds depends on the process's quota, which the other tests in this
// binary share while running in parallel; `tests/sealed_lock.rs` checks locking in a
// process of its own. Here: whatever the lock outcome, nothing panics and sealing works.
#[test]
fn sealing_works_whatever_the_lock_outcome() {
    let keys: Vec<_> = (0..64).map(|_| Prekey::new()).collect();
    for k in &keys {
        if let Err(e) = k.lock_status() {
            assert!(
                e.raw_os_error().is_some() || e.page_too_large().is_some(),
                "a lock refusal says why: an OS code, or a page too large to own"
            );
        }
        let s = SealedFixed::seal(Fixed::new([7u8; 32]), k);
        s.with_secret(|b| assert_eq!(b[0], 7));
    }
}

#[test]
fn sealed_roles_seal_and_unseal_their_own_role() {
    let prekey = Prekey::new();
    let mut s = SealedDbKey::seal(DbKey::new([2u8; 32]), &prekey);
    assert_eq!(s.len(), 32);
    s.with_secret_mut(|k| k[0] = 3);
    s.with_secret(|k| assert_eq!(k[..2], [3, 2]));
    let back: DbKey = s.unseal();
    back.with_secret(|k| assert_eq!(k[..2], [3, 2]));
}

// Imported here, not at the top: a scope that has both `RevealScoped` and `RevealSecret`
// sees two `with_secret` methods on `Fixed` (E0034). See the `scoped` module docs.
#[test]
fn with_role_hands_the_role_and_with_role_mut_reseals_it() {
    fn key_byte(k: &AppKey) -> u8 {
        k.with_secret(|b| b[0])
    }
    let prekey = Prekey::new();
    let mut s = SealedAppKey::seal(AppKey::new([7u8; 32]), &prekey);
    assert_eq!(s.with_role(key_byte), 7);
    let r = s.with_role_mut(|k: &mut AppKey| {
        secure_gate::RevealSecretMut::with_secret_mut(k, |b| b[0] = 8);
        "done"
    });
    assert_eq!(r, "done");
    assert_eq!(s.with_role(key_byte), 8);
    s.unseal().with_secret(|b| assert_eq!(b[0], 8));
}

#[test]
fn a_panic_inside_with_role_mut_leaves_the_sealed_role_unchanged() {
    let prekey = Prekey::new();
    let mut s = SealedDbKey::seal(DbKey::new([1u8; 32]), &prekey);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.with_role_mut(|k: &mut DbKey| {
            secure_gate::RevealSecretMut::with_secret_mut(k, |b| b[0] = 2);
            panic!("closure failed");
        })
    }));
    assert!(result.is_err());
    s.with_secret(|b| assert_eq!(b[0], 1));
}

fn first_byte<S: secure_gate::scoped::RevealScoped<Inner = [u8; 32]>>(s: &S) -> u8 {
    secure_gate::scoped::RevealScoped::with_secret(s, |b| b[0])
}

#[test]
fn reveal_scoped_takes_plain_sealed_and_role_types_alike() {
    let prekey = Prekey::new();
    assert_eq!(first_byte(&Fixed::new([1u8; 32])), 1);
    assert_eq!(first_byte(&AppKey::new([2u8; 32])), 2);
    assert_eq!(
        first_byte(&SealedFixed::seal(Fixed::new([3u8; 32]), &prekey)),
        3
    );
    assert_eq!(
        first_byte(&SealedAppKey::seal(AppKey::new([4u8; 32]), &prekey)),
        4
    );
}

#[test]
fn sealed_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Prekey>();
    assert_send_sync::<SealedFixed<32>>();
    assert_send_sync::<SealedDynamic<String>>();
    assert_send_sync::<SealedAppKey>();
}

#[test]
fn sealed_values_open_from_other_threads() {
    let prekey = Prekey::new();
    let s = Arc::new(SealedFixed::seal(Fixed::new([6u8; 32]), &prekey));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.with_secret(|b| b[0]))
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), 6);
    }
}
