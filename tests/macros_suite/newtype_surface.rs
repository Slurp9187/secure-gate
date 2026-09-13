//! macros_suite/newtype_surface.rs — full forwarded surface + derive passthrough
use rand::SeedableRng;
use secure_gate::{
    dynamic_newtype, fixed_newtype, ConstantTimeEq, RevealSecret, RevealSecretMut, SecretLen,
    ToBase32, ToBase64Url, ToBech32, ToBech32m, ToHex,
};

fixed_newtype!(pub EncKey, 32);
fixed_newtype!(pub Big, 900, "A secret larger than the default bech32 code length admits.");
fixed_newtype!(pub MacKey, 32, "MAC key.", derive: [ConstantTimeEq]);
dynamic_newtype!(pub Token, Vec<u8>, derive: [ConstantTimeEq]);
dynamic_newtype!(pub ApiKey, String, "API key.", derive: [ConstantTimeEq]);
dynamic_newtype!(pub Wide, generic Vec<u32>);
// The `Fixed` counterpart of the same bargain: an AES-256 expanded key schedule is
// `[u32; 60]`, as secret as the key it came from and not a byte array.
fixed_newtype!(pub RoundKeys, generic [u32; 60]);
// All four argument shapes of the `generic` form, because two arms both opening
// `generic $inner:ty,` cannot coexist in `macro_rules!` — the optional-group
// formulation that makes this work is easy to regress into four arms that do not.
fixed_newtype!(pub Documented, generic [u32; 4], "A documented generic newtype.");
fixed_newtype!(pub Derived, generic [u32; 4], derive: [FromWrapper]);
fixed_newtype!(
    pub DocumentedAndDerived,
    generic [u32; 4],
    "Both a doc string and a derive list.",
    derive: [IntoWrapper]
);

#[test]
fn fixed_full_surface() {
    let k = EncKey::from_random();
    let mut rng = rand::rngs::StdRng::from_seed([3u8; 32]);
    let r = EncKey::from_rng(&mut rng).unwrap();
    assert_eq!((k.len(), r.len()), (32, 32));

    let h = EncKey::try_from_hex(&"ab".repeat(32)).unwrap();
    assert!(h.to_hex().into_inner().starts_with("abab"));
    assert!(h.to_hex_upper().into_inner().starts_with("ABAB"));
    let base32_str = h.to_base32().into_inner();
    assert_eq!(
        EncKey::try_from_base32(&base32_str)
            .unwrap()
            .to_hex()
            .into_inner(),
        h.to_hex().into_inner()
    );
    let b64 = h.to_base64url().into_inner();
    assert_eq!(
        EncKey::try_from_base64url(&b64)
            .unwrap()
            .to_hex()
            .into_inner(),
        h.to_hex().into_inner()
    );
    let bech32_str = h
        .try_to_bech32("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    assert_eq!(
        EncKey::try_from_bech32(&bech32_str, "sg")
            .unwrap()
            .to_hex()
            .into_inner(),
        h.to_hex().into_inner()
    );
    assert!(EncKey::try_from_bech32_unchecked(&bech32_str).is_ok());
    let bech32m_str = h
        .try_to_bech32m("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    assert_eq!(
        EncKey::try_from_bech32m(&bech32m_str, "sg")
            .unwrap()
            .to_hex()
            .into_inner(),
        h.to_hex().into_inner()
    );
    assert!(EncKey::try_from_bech32m_unchecked(&bech32m_str).is_ok());
    assert_eq!(h.to_base32().into_inner().len(), base32_str.len());
    assert_eq!(h.to_base64url().into_inner().len(), b64.len());
    assert!(h.try_to_bech32("sg", secure_gate::Case::Lower).is_ok());
    assert!(h.try_to_bech32m("sg", secure_gate::Case::Lower).is_ok());
}

#[test]
fn dynamic_vec_full_surface() {
    let t = Token::from_random(8);
    let mut rng = rand::rngs::StdRng::from_seed([4u8; 32]);
    let r = Token::from_rng(8, &mut rng).unwrap();
    assert_eq!((t.len(), r.len()), (8, 8));

    let h = Token::try_from_hex("deadbeef").unwrap();
    assert_eq!(h.to_hex().into_inner(), "deadbeef");
    let base32_str = h.to_base32().into_inner();
    assert_eq!(base32_str, "32W353Y");
    assert_eq!(
        Token::try_from_base32(&base32_str)
            .unwrap()
            .to_hex()
            .into_inner(),
        "deadbeef"
    );
    assert_eq!(h.to_base32().into_inner().len(), base32_str.len());
    let b64 = h.to_base64url().into_inner();
    assert_eq!(
        Token::try_from_base64url(&b64)
            .unwrap()
            .to_hex()
            .into_inner(),
        "deadbeef"
    );
    let bech32_str = h
        .try_to_bech32("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    assert_eq!(
        Token::try_from_bech32(&bech32_str, "sg")
            .unwrap()
            .to_hex()
            .into_inner(),
        "deadbeef"
    );
    assert!(h.try_to_bech32m("sg", secure_gate::Case::Lower).is_ok());
}

#[test]
fn derive_passthrough_reaches_front_ends() {
    // Previously the derive: list was reachable only via the base macro.
    assert!(MacKey::new([1u8; 32]).ct_eq(&MacKey::new([1u8; 32])));
    assert!(Token::try_from_hex("00")
        .unwrap()
        .ct_eq(&Token::try_from_hex("00").unwrap()));
    let a: ApiKey = "x".into();
    assert!(a.ct_eq(&ApiKey::new(String::from("x"))));
    assert_eq!(Wide::new(vec![1u32]).with_secret(|v| v.len()), 1);
}

/// The `_sized` bech32 / bech32m DECODE constructors forwarded by the newtype macros.
///
/// Adversarial review of the refactor found that only the encode side had been
/// forwarded: a newtype could emit a 900-byte secret at a custom code length and then
/// had no way to read it back. `dynamic_newtype!` was additionally missing the plain
/// `_unchecked` and every bech32m decode constructor. All of that is exercised here.
#[test]
fn newtype_forwards_sized_bech32_decode() {
    use secure_gate::bech32_code_length;

    // ── fixed_newtype!: 900 bytes needs more than the 1023-character default ──
    const N: usize = bech32_code_length(2, 900);
    let big = Big::from_random();

    let s = big
        .try_to_bech32_sized::<N>("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    assert!(
        Big::try_from_bech32(&s, "sg").is_err(),
        "900 bytes must exceed the default"
    );
    let back = Big::try_from_bech32_sized::<N>(&s, "sg").unwrap();
    assert_eq!(back.expose_secret(), big.expose_secret());
    assert!(Big::try_from_bech32_unchecked_sized::<N>(&s).is_ok());
    assert!(
        Big::try_from_bech32_sized::<N>(&s, "xx").is_err(),
        "HRP still checked"
    );

    let m = big
        .try_to_bech32m_sized::<N>("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    let back = Big::try_from_bech32m_sized::<N>(&m, "sg").unwrap();
    assert_eq!(back.expose_secret(), big.expose_secret());
    assert!(Big::try_from_bech32m_unchecked_sized::<N>(&m).is_ok());
    assert!(
        Big::try_from_bech32_sized::<N>(&m, "sg").is_err(),
        "bech32m never decodes as bech32"
    );

    // ── dynamic_newtype!: sized, plus the plain constructors it never had ──
    let t = Token::from_random(900);
    let ts = t
        .try_to_bech32_sized::<N>("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    let back = Token::try_from_bech32_sized::<N>(&ts, "sg").unwrap();
    assert_eq!(back.expose_secret(), t.expose_secret());
    assert!(Token::try_from_bech32_unchecked_sized::<N>(&ts).is_ok());

    let tm = t
        .try_to_bech32m_sized::<N>("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    let back = Token::try_from_bech32m_sized::<N>(&tm, "sg").unwrap();
    assert_eq!(back.expose_secret(), t.expose_secret());
    assert!(Token::try_from_bech32m_unchecked_sized::<N>(&tm).is_ok());

    let small = Token::from_random(8);
    let ss = small
        .try_to_bech32("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    assert!(Token::try_from_bech32_unchecked(&ss).is_ok());
    let sm = small
        .try_to_bech32m("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    assert!(Token::try_from_bech32m(&sm, "sg").is_ok());
    assert!(Token::try_from_bech32m_unchecked(&sm).is_ok());
    assert!(
        Token::try_from_bech32m(&sm, "xx").is_err(),
        "HRP still checked"
    );
}

/// The `_sized` bech32 / bech32m encode methods forwarded by the newtype macros.
///
/// The macros expand a `ToBech32` / `ToBech32m` impl per newtype; a const-generic
/// method is easy to omit from one of the four expansion sites, and the omission
/// only shows up at a call site like this one.
#[test]
fn newtype_forwards_sized_bech32_methods() {
    use secure_gate::bech32_code_length;

    let k = EncKey::try_from_hex(&"cd".repeat(32)).unwrap();

    // Fixed newtype, both checksums, sized against the default.
    const N: usize = bech32_code_length(2, 32);
    let b32 = k
        .try_to_bech32_sized::<N>("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    assert_eq!(
        b32,
        k.try_to_bech32("sg", secure_gate::Case::Lower)
            .unwrap()
            .into_inner()
    );
    assert_eq!(b32.len(), N);
    assert!(k
        .try_to_bech32_sized::<N>("sg", secure_gate::Case::Lower)
        .is_ok());

    let b32m = k
        .try_to_bech32m_sized::<N>("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    assert_eq!(
        b32m,
        k.try_to_bech32m("sg", secure_gate::Case::Lower)
            .unwrap()
            .into_inner()
    );
    assert!(k
        .try_to_bech32m_sized::<N>("sg", secure_gate::Case::Lower)
        .is_ok());
    assert_ne!(b32, b32m);

    // Dynamic newtype, with a payload past the default code length.
    let big = Token::from_random(900);
    assert!(
        big.try_to_bech32("sg", secure_gate::Case::Lower).is_err(),
        "900 bytes exceeds 1023 chars"
    );
    let wide = big
        .try_to_bech32_sized::<2048>("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    assert!(wide.starts_with("sg1"));
    let wide_m = big
        .try_to_bech32m_sized::<2048>("sg", secure_gate::Case::Lower)
        .unwrap()
        .into_inner();
    assert!(wide_m.starts_with("sg1"));
    assert_ne!(
        wide, wide_m,
        "the two checksums must not produce the same string"
    );
}

/// `fixed_newtype!`'s `generic` arm emits the shape-independent surface and nothing more:
/// construction, the access traits, redacted `Debug`, zeroization. No `SecretLen` and no
/// encoders, because neither has a meaning for an arbitrary inner type — the same trade
/// `dynamic_newtype!`'s generic arm makes, verified here rather than assumed.
#[test]
fn fixed_generic_arm_surface() {
    let mut k = RoundKeys::new([7u32; 60]);
    assert_eq!(k.with_secret(|w| w[0]), 7);
    k.with_secret_mut(|w| w[0] = 9);
    assert_eq!(k.expose_secret()[0], 9);
    assert_eq!(format!("{k:?}"), "[REDACTED]");
    // `#[repr(transparent)]` over `Fixed<[u32; 60]>`: 60 words, 4 bytes each.
    assert_eq!(core::mem::size_of::<RoundKeys>(), 240);
}

/// The `generic` form accepts a doc literal and a `derive:` list in any combination,
/// matching `dynamic_newtype!`'s generic arm. Asserted by construction rather than by
/// reading the macro: the declarations above would not compile otherwise.
#[test]
fn fixed_generic_arm_accepts_doc_and_derive() {
    use secure_gate::Fixed;
    assert_eq!(Documented::new([1u32; 4]).with_secret(|w| w[0]), 1);
    // `FromWrapper` is inbound only: a base value can enter the role.
    let from_base = Derived::from_wrapper(Fixed::new([2u32; 4]));
    assert_eq!(from_base.with_secret(|w| w[0]), 2);
    // `IntoWrapper` is outbound only: material can leave toward the base.
    let base: Fixed<[u32; 4]> = DocumentedAndDerived::new([3u32; 4]).into_wrapper();
    assert_eq!(base.expose_secret()[0], 3);
}
