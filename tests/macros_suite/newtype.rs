//! macros_suite/newtype.rs — fixed_newtype! / dynamic_newtype! macro tests

use secure_gate::{RevealSecret, SecretLen, dynamic_newtype, fixed_newtype};

// Compare directly with a plain type alias:
//   type Aes256Key = Fixed<[u8; 32]>;        -> a second name, structural
//   fixed_newtype!(pub EncKey, 32);          -> a distinct type, nominal
fixed_newtype!(pub EncKey, 32);
fixed_newtype!(pub MacKey, 32, "HMAC-SHA256 key. Never used for encryption.");
fixed_newtype!(pub Nonce, 12);

dynamic_newtype!(pub ApiKey, String);
dynamic_newtype!(pub SessionToken, Vec<u8>);
dynamic_newtype!(pub WebhookSecret, String, "Signing secret for inbound webhooks.");

#[test]
fn fixed_full_inherent_surface_returns_self() {
    // Constructors return the NEWTYPE, not Fixed<[u8; 32]>.
    let a: EncKey = EncKey::new([1u8; 32]);
    let b: EncKey = [2u8; 32].into(); // From<[u8; N]> now works
    let c: EncKey = EncKey::new_with(|buf| buf[0] = 3);
    let d: EncKey = (&[4u8; 32][..]).try_into().unwrap(); // TryFrom<&[u8]>
    assert_eq!((a.len(), b.len(), c.len(), d.len()), (32, 32, 32, 32));

    let n = Nonce::new([0u8; 12]);
    assert_eq!(n.len(), 12);
}

#[cfg(feature = "rand")]
#[test]
fn rand_returns_self() {
    let k: EncKey = EncKey::from_random(); // <- Self, no from_wrapper needed
    assert_eq!(k.len(), 32);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hex_roundtrips_through_the_newtype() {
    use secure_gate::ToHex;

    let k: EncKey = EncKey::try_from_hex(&"ab".repeat(32)).unwrap();
    assert!(k.to_hex().into_inner().starts_with("abab")); // no as_wrapper()
    assert_eq!(k.to_hex_upper().into_inner().len(), 64);
}

#[test]
fn dynamic_arms_pick_the_right_api() {
    let api: ApiKey = "sk_live_xyz".into(); // From<&str> on the String arm
    assert_eq!(api.expose_secret(), "sk_live_xyz");

    // `len` is fixed by the caller up front and the slot is pre-zeroed, so a
    // closure that fills the *whole* slot (`new_with(3, |v| v.copy_from_slice(b"abc"))`,
    // asserting only `len() == 3`) only ever proves the newtype echoes back the
    // `len` the test itself passed in — an arm that ignored `f`, or built the
    // wrapper from a throwaway scratch buffer and a separate `vec![0u8; len]`,
    // would still report `len() == 3` and pass. Filling just the first 3 of 8
    // bytes and reading both halves back is what pins the fill to the
    // wrapper's own storage: the payload has to be read back (not just its
    // length), and the untouched tail has to still be the pre-zeroing, not
    // whatever a scratch buffer happened to hold.
    let tok = SessionToken::new_with(8, |v| v[..3].copy_from_slice(b"abc"));
    assert_eq!(tok.len(), 8);
    assert_eq!(&tok.expose_secret()[..3], b"abc");
    assert_eq!(&tok.expose_secret()[3..], &[0u8; 5]);

    let hook = WebhookSecret::new(String::from("whsec_1"));
    assert_eq!(format!("{hook:?}"), "[REDACTED]");
}

/// `try_new_with` on the `Vec<u8>` arm, exercised end to end.
///
/// `dynamic_newtype!` does not forward this constructor transparently — it
/// re-wraps with `Ok(Self(<Dynamic<Vec<u8>>>::try_new_with(len, f)?))`, and its
/// own rustdoc makes a security claim about the partial write being wiped on
/// `Err`. Nothing in this suite called it before this test, on either the
/// success or the failure path. That gap matters for the same reason
/// `tests/lifecycle_trace_handoff.rs` gives the `Fixed` side a dedicated test
/// (`newtype_try_new_with_wipes_on_error_and_not_on_success`): a forward that
/// silently rebuilt the value on `Err`, or dropped the caller's error type for
/// its own, would still pass a test that only checked `is_err()`.
///
/// The success half mirrors the partial-fill check above — length, payload,
/// and zero tail all read back through the newtype, not just through the
/// inner `Dynamic` the macro wraps. The failure half pins that the caller's
/// own error type comes back out unchanged, byte for byte, rather than being
/// mapped, boxed, or discarded in favor of `()`.
///
/// What this test cannot see: whether the `Err` path actually *wipes* the
/// partial write before returning. That needs the allocator proxy
/// `tests/heap_zeroize.rs` already uses for exactly this claim on `Dynamic`
/// itself — a `SessionToken`-level equivalent belongs there, not here.
#[test]
fn session_token_try_new_with_reads_back_and_propagates_errors() {
    #[derive(Debug, PartialEq, Eq)]
    struct ReadError(&'static str);

    // Success: the fill reaches the wrapper's own storage (length and payload
    // both read back through the newtype), and a short fill leaves the
    // untouched tail as the pre-zeroing, exactly as `new_with` does above.
    let tok = SessionToken::try_new_with(8, |v| {
        v[..3].copy_from_slice(b"abc");
        Ok::<(), ReadError>(())
    })
    .expect("closure succeeded");
    assert_eq!(tok.len(), 8);
    assert_eq!(&tok.expose_secret()[..3], b"abc");
    assert_eq!(&tok.expose_secret()[3..], &[0u8; 5]);

    // Failure: the caller's error type comes back out unchanged. A forward
    // that rebuilt `Self` regardless of the closure's result, or that mapped
    // the error away, would fail this even though `is_err()` alone would not
    // have caught it.
    let err = SessionToken::try_new_with(8, |v| {
        v[..3].copy_from_slice(b"bad");
        Err(ReadError("device error"))
    })
    .unwrap_err();
    assert_eq!(err, ReadError("device error"));
}

#[cfg(all(feature = "encoding-hex", feature = "std"))]
#[test]
fn vec_arm_gets_bytes_only_api() {
    use secure_gate::ToHex;
    use std::io::{Read, Write};
    let mut tok = SessionToken::new(vec![]);
    tok.write_all(b"\xde\xad").unwrap(); // io::Write forwarded
    assert_eq!(tok.to_hex().into_inner(), "dead"); // hex on Vec<u8> arm only
    let mut read_back = Vec::new(); // as_reader forwarded (io::Read)
    tok.as_reader().read_to_end(&mut read_back).unwrap();
    assert_eq!(read_back, b"\xde\xad");
}

#[test]
fn roles_still_do_not_mix() {
    fn seal(_enc: &EncKey, _mac: &MacKey) {}
    seal(&EncKey::new([1u8; 32]), &MacKey::new([2u8; 32]));
    // seal(&MacKey::new(..), &EncKey::new(..)) -> E0308
}
