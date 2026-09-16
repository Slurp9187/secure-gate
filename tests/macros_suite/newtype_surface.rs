//! macros_suite/newtype_surface.rs — full forwarded surface + derive passthrough
use rand::SeedableRng;
use secure_gate::{
    ConstantTimeEq, RevealSecret, RevealSecretMut, SecretLen, ToBase32, ToBase64Url, ToBech32,
    ToBech32m, ToHex, dynamic_newtype, fixed_newtype,
};

fixed_newtype!(pub EncKey, 32);
fixed_newtype!(pub Big, 900, "A secret larger than the default bech32 code length admits.");
fixed_newtype!(pub MacKey, 32, "MAC key.");
// A derive list either side of where the `ConstantTimeEq` token used to sit.
fixed_newtype!(pub SessionTag, 32, derive: [FromWrapper, IntoWrapper]);
dynamic_newtype!(pub Token, Vec<u8>);
dynamic_newtype!(pub ApiKey, String, "API key.");
// The `dynamic_newtype!` counterparts of the automatic-`ct_eq` pins below.
dynamic_newtype!(pub BareToken, Vec<u8>);
dynamic_newtype!(pub BareApiKey, String, "No derive list.");
dynamic_newtype!(pub MixedToken, Vec<u8>, derive: [FromWrapper, IntoWrapper]);
dynamic_newtype!(pub Wide, generic Vec<u32>);
// The documented remainder of the `generic Vec<u8>` / `generic String` reject.
//
// Those two are refused by literal token, which is a *spelling* guard and not a
// type-level one: a path-qualified `Vec<u8>` is a different token sequence, so it
// still reaches the reduced arm. That is pinned here rather than left as a claim
// in prose, so anyone who later closes the gap has to change a test and make the
// decision deliberately. A token deny-list does not become type-level by getting
// longer, which is why this is documented instead of chased.
dynamic_newtype!(pub QualifiedBytes, generic std::vec::Vec<u8>);
// The `Fixed` counterpart of the same bargain: an AES-256 expanded key schedule is
// `[u32; 60]`, as secret as the key it came from and not a byte array.
fixed_newtype!(pub RoundKeys, generic [u32; 60]);
// All four argument shapes of the `generic` form, because two arms both opening
// `generic $inner:ty,` cannot coexist in `macro_rules!` — the optional-group
// formulation that makes this work is easy to regress into four arms that do not.
// These are literal arrays, so they exercise the *array* arm's tails.
fixed_newtype!(pub Documented, generic [u32; 4], "A documented generic newtype.");
fixed_newtype!(pub Derived, generic [u32; 4], derive: [FromWrapper]);
fixed_newtype!(
    pub DocumentedAndDerived,
    generic [u32; 4],
    "Both a doc string and a derive list.",
    derive: [IntoWrapper]
);
// And the same four tails on the *opaque* arm, which otherwise has none: every literal
// array above now matches the array arm, so without these a regression splitting the
// opaque arm's optional groups into four arms would pass every test. `generic Schedule`
// is a single ident rather than a `[...]` token group, so it lands on the opaque arm
// even though `Schedule` resolves to the very same array.
type Schedule = [u32; 4];
fixed_newtype!(pub Opaque, generic Schedule);
fixed_newtype!(pub OpaqueDocumented, generic Schedule, "An opaque generic newtype.");
fixed_newtype!(pub OpaqueDerived, generic Schedule, derive: [FromWrapper]);
fixed_newtype!(
    pub OpaqueDocumentedAndDerived,
    generic Schedule,
    "Both a doc string and a derive list, opaque.",
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
    // The derive: list reaches the front-end arms, not only the base macro.
    // `ConstantTimeEq` is no longer among the options it can carry — the shaped
    // arms emit that themselves — so these pin the automatic impl instead.
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

/// `ct_eq` is automatic on the size-literal arm, and cannot be asked for.
///
/// A plain `type Name = Fixed<[u8; N]>;` has always carried `ConstantTimeEq`, from
/// the wrapper's own impl. Until 0.9.0-rc.11 the newtype did not, so the spelling
/// this crate recommends as the safer of the two offered *less* unless the
/// declaration also named `derive: [ConstantTimeEq]` — the extra token sat on the
/// side the documentation steers people toward. The impl now arrives unasked, and
/// naming the token is a hard error rather than a no-op: the shaped arms emit it
/// themselves, so a second one from the `derive:` list is `E0119`. Nothing below
/// spells it.
#[test]
fn ct_eq_is_automatic_for_byte_array_newtypes() {
    // `EncKey` is declared with no `derive:` list at all.
    assert!(EncKey::new([7u8; 32]).ct_eq(&EncKey::new([7u8; 32])));
    assert!(!EncKey::new([7u8; 32]).ct_eq(&EncKey::new([8u8; 32])));

    // A length well past the 32-element ceiling `Default` would have imposed.
    assert!(Big::new([3u8; 900]).ct_eq(&Big::new([3u8; 900])));
    assert!(!Big::new([3u8; 900]).ct_eq(&Big::new([4u8; 900])));

    // A doc string and no derive list: still automatic.
    assert!(MacKey::new([1u8; 32]).ct_eq(&MacKey::new([1u8; 32])));

    // Automatic alongside an unrelated derive list, in both directions.
    assert!(SessionTag::new([2u8; 32]).ct_eq(&SessionTag::new([2u8; 32])));
    let wrapped = SessionTag::from_wrapper(secure_gate::Fixed::new([2u8; 32]));
    assert!(wrapped.ct_eq(&SessionTag::new([2u8; 32])));
    assert_eq!(wrapped.into_wrapper().expose_secret(), &[2u8; 32]);
}

/// The same, for `dynamic_newtype!`'s `String` and `Vec<u8>` arms.
///
/// `Dynamic<T>` implements `ConstantTimeEq` for any `T` that does, so
/// `type Name = Dynamic<String>;` always had `ct_eq` and the newtype did not. The
/// heap arms carried the identical asymmetry to the size-literal one and were
/// corrected in the same release.
#[test]
fn ct_eq_is_automatic_for_string_and_vec_newtypes() {
    // No derive list at all.
    let a: BareApiKey = "x".into();
    assert!(a.ct_eq(&BareApiKey::new(String::from("x"))));
    assert!(!a.ct_eq(&BareApiKey::new(String::from("y"))));

    let t = BareToken::try_from_hex("00ff").unwrap();
    assert!(t.ct_eq(&BareToken::try_from_hex("00ff").unwrap()));
    assert!(!t.ct_eq(&BareToken::try_from_hex("00fe").unwrap()));

    // Differing lengths compare unequal rather than panicking — the documented
    // short-circuit, and the reason length is not covered by the guarantee.
    assert!(!t.ct_eq(&BareToken::try_from_hex("00").unwrap()));

    // No derive list on the `Vec<u8>` arm either.
    assert!(
        Token::try_from_hex("00")
            .unwrap()
            .ct_eq(&Token::try_from_hex("00").unwrap())
    );

    // Automatic alongside an unrelated derive list, in both directions.
    let m = MixedToken::from_wrapper(secure_gate::Dynamic::new(vec![9u8, 9]));
    assert!(m.ct_eq(&MixedToken::new(vec![9u8, 9])));
    assert_eq!(m.into_wrapper().expose_secret(), &vec![9u8, 9]);
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
    assert!(
        k.try_to_bech32_sized::<N>("sg", secure_gate::Case::Lower)
            .is_ok()
    );

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
    assert!(
        k.try_to_bech32m_sized::<N>("sg", secure_gate::Case::Lower)
            .is_ok()
    );
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

/// `fixed_newtype!`'s array arm emits the shape-independent surface — construction
/// (`new` and `new_with`), the access traits, redacted `Debug`, zeroization — plus
/// `SecretLen`, which an array shape gives a correct answer for in both units. Still
/// no encoders: hex over `[u32]` has no defined byte order, and the canonical encoding
/// of a key schedule is not a raw word dump anyway.
#[test]
fn fixed_generic_arm_surface() {
    let mut k = RoundKeys::new([7u32; 60]);
    assert_eq!(k.with_secret(|w| w[0]), 7);
    let filled = RoundKeys::new_with(|w| w.fill(3));
    assert_eq!(filled.with_secret(|w| w[0]), 3);
    k.with_secret_mut(|w| w[0] = 9);
    assert_eq!(k.expose_secret()[0], 9);
    assert_eq!(format!("{k:?}"), "[REDACTED]");
    // `#[repr(transparent)]` over `Fixed<[u32; 60]>`: 60 words, 4 bytes each.
    assert_eq!(core::mem::size_of::<RoundKeys>(), 240);
    // The array arm's own `SecretLen`, reached without `IntoWrapper`. `len` counts
    // elements and `byte_len` multiplies by `size_of::<u32>()`; for a byte array the
    // two coincide, which is why only a non-byte element type pins the distinction.
    assert_eq!((k.len(), k.byte_len()), (60, 240));
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

/// The opaque arm accepts the same four tails, and keeps the reduced surface while doing
/// it. Spelled through an alias so the tokens are a single ident: the array arm matches
/// on shape, and a name hides the shape from it.
#[test]
fn fixed_opaque_arm_accepts_doc_and_derive() {
    use secure_gate::Fixed;
    assert_eq!(Opaque::new([1u32; 4]).with_secret(|w| w[0]), 1);
    assert_eq!(OpaqueDocumented::new([2u32; 4]).with_secret(|w| w[0]), 2);
    let from_base = OpaqueDerived::from_wrapper(Fixed::new([3u32; 4]));
    assert_eq!(from_base.with_secret(|w| w[0]), 3);
    let base: Fixed<Schedule> = OpaqueDocumentedAndDerived::new([4u32; 4]).into_wrapper();
    assert_eq!(base.expose_secret()[0], 4);
    // The reduced surface is still reduced: no `len()` of its own, but the same answer
    // is one audited `as_wrapper()` away, because `Fixed<Schedule>` *is* `Fixed<[u32; 4]>`.
    assert_eq!(base.len(), 4);
}
