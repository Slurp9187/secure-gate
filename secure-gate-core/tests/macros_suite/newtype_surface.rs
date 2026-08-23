//! macros_suite/newtype_surface.rs — full forwarded surface + derive passthrough
use rand::SeedableRng;
use secure_gate::{
    ConstantTimeEq, RevealSecret, SecretLen, ToBase64Url, ToBech32, ToBech32m, ToHex,
    dynamic_newtype, fixed_newtype,
};

fixed_newtype!(pub EncKey, 32);
fixed_newtype!(pub MacKey, 32, "MAC key.", derive: [ConstantTimeEq]);
dynamic_newtype!(pub Token, Vec<u8>, derive: [ConstantTimeEq]);
dynamic_newtype!(pub ApiKey, String, "API key.", derive: [ConstantTimeEq]);
dynamic_newtype!(pub Wide, generic Vec<u32>);

#[test]
fn fixed_full_surface() {
    let k = EncKey::from_random();
    let mut rng = rand::rngs::StdRng::from_seed([3u8; 32]);
    let r = EncKey::from_rng(&mut rng).unwrap();
    assert_eq!((k.len(), r.len()), (32, 32));

    let h = EncKey::try_from_hex(&"ab".repeat(32)).unwrap();
    assert!(h.to_hex().starts_with("abab"));
    assert!(h.to_hex_upper().starts_with("ABAB"));
    let b64 = h.to_base64url();
    assert_eq!(
        EncKey::try_from_base64url(&b64).unwrap().to_hex(),
        h.to_hex()
    );
    let b32 = h.try_to_bech32("sg").unwrap();
    assert_eq!(
        EncKey::try_from_bech32(&b32, "sg").unwrap().to_hex(),
        h.to_hex()
    );
    assert!(EncKey::try_from_bech32_unchecked(&b32).is_ok());
    let b32m = h.try_to_bech32m("sg").unwrap();
    assert_eq!(
        EncKey::try_from_bech32m(&b32m, "sg").unwrap().to_hex(),
        h.to_hex()
    );
    assert!(EncKey::try_from_bech32m_unchecked(&b32m).is_ok());
    assert_eq!(h.to_base64url_zeroizing().len(), b64.len());
    assert!(h.try_to_bech32_zeroizing("sg").is_ok());
    assert!(h.try_to_bech32m_zeroizing("sg").is_ok());
}

#[test]
fn dynamic_vec_full_surface() {
    let t = Token::from_random(8);
    let mut rng = rand::rngs::StdRng::from_seed([4u8; 32]);
    let r = Token::from_rng(8, &mut rng).unwrap();
    assert_eq!((t.len(), r.len()), (8, 8));

    let h = Token::try_from_hex("deadbeef").unwrap();
    assert_eq!(h.to_hex(), "deadbeef");
    let b64 = h.to_base64url();
    assert_eq!(
        Token::try_from_base64url(&b64).unwrap().to_hex(),
        "deadbeef"
    );
    let b32 = h.try_to_bech32("sg").unwrap();
    assert_eq!(
        Token::try_from_bech32(&b32, "sg").unwrap().to_hex(),
        "deadbeef"
    );
    assert!(h.try_to_bech32m("sg").is_ok());
}

#[test]
fn derive_passthrough_reaches_front_ends() {
    // Previously the derive: list was reachable only via the base macro.
    assert!(MacKey::new([1u8; 32]).ct_eq(&MacKey::new([1u8; 32])));
    assert!(
        Token::try_from_hex("00")
            .unwrap()
            .ct_eq(&Token::try_from_hex("00").unwrap())
    );
    let a: ApiKey = "x".into();
    assert!(a.ct_eq(&ApiKey::new(String::from("x"))));
    assert_eq!(Wide::new(vec![1u32]).with_secret(|v| v.len()), 1);
}
