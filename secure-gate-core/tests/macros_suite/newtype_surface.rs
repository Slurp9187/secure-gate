//! macros_suite/newtype_surface.rs — full forwarded surface + derive passthrough
use rand::SeedableRng;
use secure_gate::{
    ConstantTimeEq, RevealSecret, SecretLen, ToBase32, ToBase64Url, ToBech32, ToBech32m, ToHex,
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
    let base32_str = h.to_base32();
    assert_eq!(
        EncKey::try_from_base32(&base32_str).unwrap().to_hex(),
        h.to_hex()
    );
    let b64 = h.to_base64url();
    assert_eq!(
        EncKey::try_from_base64url(&b64).unwrap().to_hex(),
        h.to_hex()
    );
    let bech32_str = h.try_to_bech32("sg").unwrap();
    assert_eq!(
        EncKey::try_from_bech32(&bech32_str, "sg").unwrap().to_hex(),
        h.to_hex()
    );
    assert!(EncKey::try_from_bech32_unchecked(&bech32_str).is_ok());
    let bech32m_str = h.try_to_bech32m("sg").unwrap();
    assert_eq!(
        EncKey::try_from_bech32m(&bech32m_str, "sg")
            .unwrap()
            .to_hex(),
        h.to_hex()
    );
    assert!(EncKey::try_from_bech32m_unchecked(&bech32m_str).is_ok());
    assert_eq!(h.to_base32_zeroizing().len(), base32_str.len());
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
    let base32_str = h.to_base32();
    assert_eq!(base32_str, "32W353Y");
    assert_eq!(
        Token::try_from_base32(&base32_str).unwrap().to_hex(),
        "deadbeef"
    );
    assert_eq!(h.to_base32_zeroizing().len(), base32_str.len());
    let b64 = h.to_base64url();
    assert_eq!(
        Token::try_from_base64url(&b64).unwrap().to_hex(),
        "deadbeef"
    );
    let bech32_str = h.try_to_bech32("sg").unwrap();
    assert_eq!(
        Token::try_from_bech32(&bech32_str, "sg").unwrap().to_hex(),
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

/// The `_sized` bech32 / bech32m methods forwarded by the newtype macros.
///
/// The macros expand a `ToBech32` / `ToBech32m` impl per newtype; a const-generic
/// method is easy to omit from one of the four expansion sites, and the omission
/// only shows up at a call site like this one.
#[test]
fn newtype_forwards_sized_bech32_methods() {
    use secure_gate::bech32_code_length;

    let k = EncKey::try_from_hex(&"cd".repeat(32)).unwrap();

    // Fixed newtype, both variants, plain and zeroizing.
    const N: usize = bech32_code_length(2, 32);
    let b32 = k.try_to_bech32_sized::<N>("sg").unwrap();
    assert_eq!(b32, k.try_to_bech32("sg").unwrap());
    assert_eq!(b32.len(), N);
    assert!(k.try_to_bech32_sized_zeroizing::<N>("sg").is_ok());

    let b32m = k.try_to_bech32m_sized::<N>("sg").unwrap();
    assert_eq!(b32m, k.try_to_bech32m("sg").unwrap());
    assert!(k.try_to_bech32m_sized_zeroizing::<N>("sg").is_ok());
    assert_ne!(b32, b32m);

    // Dynamic newtype, with a payload past the default code length.
    let big = Token::from_random(900);
    assert!(big.try_to_bech32("sg").is_err(), "900 bytes exceeds 1023 chars");
    let wide = big.try_to_bech32_sized::<2048>("sg").unwrap();
    assert!(wide.starts_with("sg1"));
    assert!(big.try_to_bech32_sized_zeroizing::<2048>("sg").is_ok());
    assert!(big.try_to_bech32m_sized::<2048>("sg").is_ok());
    assert!(big.try_to_bech32m_sized_zeroizing::<2048>("sg").is_ok());
}
