//! macros_suite/newtype_conversion.rs — conversion discipline (R2/R7/Q7)
//! from the downstream requirements in `docs/secure-gate-requested-newtyping-requirements.md`.

use secure_gate::{Dynamic, RevealSecret, dynamic_alias, dynamic_newtype, fixed_newtype};

dynamic_alias!(pub FileId, String);
dynamic_newtype!(pub PublicId, String);
dynamic_newtype!(pub Opened, String, derive: [WrapperAccess]);
fixed_newtype!(pub FileKey32, 32);

#[test]
fn r7_new_accepts_str_and_string() {
    // Matches the hand-written `new(impl Into<String>)` shape.
    assert_eq!(PublicId::new("literal").expose_secret(), "literal");
    assert_eq!(
        PublicId::new(String::from("owned")).expose_secret(),
        "owned"
    );
    assert_eq!(FileKey32::new([1u8; 32]).expose_secret()[0], 1);
}

#[test]
fn r2_the_only_default_path_is_a_with_secret_round_trip() {
    let file_id: FileId = "id".into();
    // No `.into()`, no `from_wrapper`: material moves only via explicit access.
    let republished = PublicId::new(file_id.with_secret(|s| s.clone()));
    assert_eq!(republished.expose_secret(), "id");
}

#[test]
fn r2_wrapper_access_is_opt_in_per_newtype() {
    let base: Dynamic<String> = Dynamic::from("x");
    let o = Opened::from_wrapper(base); // only because of derive: [WrapperAccess]
    assert_eq!(o.as_wrapper().expose_secret(), "x");
    let _back: Dynamic<String> = o.into_wrapper();
    // `PublicId::from_wrapper` does not exist — pinned by the compile-fail case.
}

fn generic_over_inner<T: RevealSecret<Inner = String>>(t: &T) -> usize {
    t.with_secret(|s| s.len())
}

#[test]
fn q7_trait_bounds_are_structural_by_design() {
    // A bound on `RevealSecret<Inner = String>` accepts every type whose inner
    // is a String — newtype or alias. Nominal identity is a property of the
    // type, not of the traits it implements; bound on the concrete type (or a
    // marker trait of your own) to exclude siblings.
    let p = PublicId::new("ab");
    let f: FileId = "abc".into();
    assert_eq!((generic_over_inner(&p), generic_over_inner(&f)), (2, 3));
}

#[cfg(feature = "serde-serialize")]
mod r5 {
    use super::*;
    use serde::{Serialize, Serializer};

    impl Serialize for PublicId {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            self.with_secret(|v| v.serialize(s))
        }
    }

    #[test]
    fn per_newtype_serialize_via_hand_written_impl() {
        let p = PublicId::new("safe-to-expose");
        assert_eq!(serde_json::to_string(&p).unwrap(), "\"safe-to-expose\"");
        // FileId (alias) and any sibling newtype stay non-serializable —
        // pinned by tests/compile-fail/newtype_sibling_not_serializable.rs.
    }
}
