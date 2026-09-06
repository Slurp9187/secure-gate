//! Composability guarantees introduced by the `RevealSecret`/`SecretLen` split
//! and the trait-based encoder surface.
//!
//! Three properties are pinned here:
//! 1. `RevealSecret` covers **every** inner type, including local user-defined
//!    ones — the `CloneableSecret`/`SerializableSecret` newtype pattern from
//!    the trait docs yields a fully usable secret.
//! 2. Encoding is generic: one function bound on `ToHex` accepts `Fixed`,
//!    `Dynamic`, and any forwarding newtype.
//! 3. `SecretLen` stays narrow: types with no meaningful length don't get one.

use secure_gate::{Fixed, RevealSecret, RevealSecretMut};
use zeroize::Zeroize;

/// The exact pattern recommended by `cloneable_secret.rs` / `serializable_secret.rs`.
struct SessionKey([u8; 32]);

impl Zeroize for SessionKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[test]
fn custom_inner_type_is_revealable() {
    // Before the split this failed: RevealSecret existed only for [T; N],
    // String, and Vec<T> inners, so Fixed<SessionKey> could be constructed,
    // cloned, and zeroized — but never read.
    let mut key = Fixed::new(SessionKey([7u8; 32]));
    assert_eq!(key.with_secret(|s| s.0[0]), 7);
    assert_eq!(key.expose_secret().0[31], 7);
    key.with_secret_mut(|s| s.0[0] = 9);
    assert_eq!(key.expose_secret_mut().0[0], 9);
    // No SecretLen impl — `key.len()` correctly does not compile.
}

#[cfg(feature = "alloc")]
#[test]
fn custom_inner_type_in_dynamic() {
    use secure_gate::Dynamic;
    let key: Dynamic<SessionKey> = Dynamic::new(SessionKey([3u8; 32]));
    assert_eq!(key.with_secret(|s| s.0[0]), 3);
}

#[cfg(feature = "cloneable")]
#[test]
// The clone *is* the assertion (`Fixed<BackupKey>: Clone` via the marker); 1.70's
// clippy flags it as redundant because the copy is only read afterwards.
#[allow(clippy::redundant_clone)]
fn cloneable_newtype_pattern_is_fully_usable() {
    use secure_gate::CloneableSecret;

    #[derive(Clone)]
    struct BackupKey([u8; 32]);
    impl Zeroize for BackupKey {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }
    impl CloneableSecret for BackupKey {}

    let original = Fixed::new(BackupKey([5u8; 32]));
    let copy = original.clone();
    // The docs' opt-in pattern now composes with access — both halves work.
    assert_eq!(
        copy.with_secret(|k| k.0[7]),
        original.with_secret(|k| k.0[7])
    );
}

#[cfg(all(feature = "ct-eq", feature = "cloneable"))]
#[test]
fn ct_eq_reaches_custom_inner_types() {
    use secure_gate::ConstantTimeEq;

    #[derive(Clone)]
    struct MacKey([u8; 32]);
    impl Zeroize for MacKey {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }
    impl ConstantTimeEq for MacKey {
        fn ct_eq(&self, other: &Self) -> bool {
            self.0.ct_eq(&other.0)
        }
    }

    let a = Fixed::new(MacKey([1u8; 32]));
    let b = Fixed::new(MacKey([1u8; 32]));
    // The wrapper-level ct_eq is generic over T: ConstantTimeEq; the widened
    // RevealSecret impl is what lets it see Fixed<MacKey> at all.
    assert!(a.ct_eq(&b));
}

#[cfg(all(feature = "serde-serialize", feature = "alloc"))]
#[test]
fn serializable_newtype_pattern_is_fully_usable() {
    use secure_gate::SerializableSecret;
    use serde::Serialize;

    #[derive(Serialize)]
    struct ExportKey([u8; 4]);
    impl Zeroize for ExportKey {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }
    impl SerializableSecret for ExportKey {}

    let key = Fixed::new(ExportKey([1, 2, 3, 4]));
    assert_eq!(serde_json::to_string(&key).unwrap(), "[1,2,3,4]");
    assert_eq!(key.with_secret(|k| k.0[3]), 4); // …and it is still readable.
}

#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
mod generic_encoding {
    use secure_gate::{Dynamic, Fixed, RevealSecret, ToHex};

    /// One bound, three shapes: Fixed, Dynamic, and a hand-rolled newtype
    /// whose only forwarding is `RevealSecret` + `ToHex`.
    fn fingerprint<S: ToHex>(secret: &S) -> String {
        secret.to_hex()
    }

    struct EncKey(Fixed<[u8; 4]>);
    impl ToHex for EncKey {
        fn to_hex(&self) -> String {
            self.0.to_hex()
        }
        fn to_hex_upper(&self) -> String {
            self.0.to_hex_upper()
        }
        fn to_hex_zeroizing(&self) -> secure_gate::EncodedSecret {
            self.0.to_hex_zeroizing()
        }
        fn to_hex_upper_zeroizing(&self) -> secure_gate::EncodedSecret {
            self.0.to_hex_upper_zeroizing()
        }
    }

    #[test]
    fn one_bound_covers_wrappers_and_newtypes() {
        let f = Fixed::new([0xABu8; 4]);
        let d: Dynamic<Vec<u8>> = Dynamic::from(&[0xABu8; 4][..]);
        let n = EncKey(Fixed::new([0xABu8; 4]));
        assert_eq!(fingerprint(&f), "abababab");
        assert_eq!(fingerprint(&d), "abababab");
        assert_eq!(fingerprint(&n), "abababab");
        // The inner-bytes blanket impl serves the closure form as before:
        assert_eq!(f.with_secret(|b| b.to_hex()), "abababab");
        let _ = d.expose_secret(); // RevealSecret still in play
    }
}

#[cfg(feature = "alloc")]
#[test]
fn secret_len_stays_narrow() {
    use secure_gate::{Dynamic, SecretLen};
    let f = Fixed::new([0u8; 16]);
    assert_eq!((f.len(), f.byte_len(), f.is_empty()), (16, 16, false));
    let d: Dynamic<String> = Dynamic::from("hunter2");
    assert_eq!((d.len(), d.byte_len(), d.is_empty()), (7, 7, false));
    let v: Dynamic<Vec<u16>> = Dynamic::new(vec![1u16, 2, 3]);
    assert_eq!((v.len(), v.byte_len()), (3, 6));
}
