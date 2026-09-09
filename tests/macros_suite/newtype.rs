//! macros_suite/newtype.rs — fixed_newtype! / dynamic_newtype! macro tests

use secure_gate::{RevealSecret, SecretLen, dynamic_newtype, fixed_newtype};

// Compare directly with the existing alias macros:
//   fixed_alias!(pub Aes256Key, 32);         -> type alias, structural
//   fixed_newtype!(pub EncKey, 32);          -> newtype, nominal
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

    let tok = SessionToken::new_with(|v| v.extend_from_slice(b"abc"));
    assert_eq!(tok.len(), 3);

    let hook = WebhookSecret::new(String::from("whsec_1"));
    assert_eq!(format!("{hook:?}"), "[REDACTED]");
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
