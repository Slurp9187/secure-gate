//! `Dynamic<[u8]>` shares `Dynamic<Vec<u8>>`'s constructors, decoders and encoders (#267):
//! each is written once over `DynamicBytes`, and the named type picks the shape.

use secure_gate::{Dynamic, RevealSecret, SecretLen};

#[test]
fn new_with_builds_an_exact_length_slice() {
    let s: Dynamic<[u8]> = Dynamic::new_with(5, |b| b.copy_from_slice(b"abcde"));
    assert_eq!(s.len(), 5);
    s.with_secret(|b| assert_eq!(b, b"abcde"));
}

#[test]
fn try_new_with_passes_the_callers_error_through() {
    let r: Result<Dynamic<[u8]>, &str> = Dynamic::try_new_with(4, |_| Err("no"));
    assert_eq!(r.err(), Some("no"));
}

#[test]
fn the_annotation_picks_the_shape_for_both() {
    let v: Dynamic<Vec<u8>> = Dynamic::new_with(3, |b| b.fill(1));
    let s: Dynamic<[u8]> = Dynamic::new_with(3, |b| b.fill(1));
    assert_eq!(v.expose_secret().as_slice(), s.expose_secret());
}

#[cfg(feature = "rand")]
#[test]
fn from_random_fills_a_slice_of_the_asked_length() {
    let s: Dynamic<[u8]> = Dynamic::from_random(32);
    assert_eq!(s.len(), 32);
    let v = Dynamic::<Vec<u8>>::from_random(32);
    assert_eq!(v.len(), 32);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn hex_round_trips_through_a_slice() {
    use secure_gate::ToHex;
    let s = Dynamic::<[u8]>::try_from_hex("deadbeef").unwrap();
    assert_eq!(s.len(), 4);
    assert_eq!(&*s.to_hex(), "deadbeef");
    assert_eq!(&*s.to_hex_upper(), "DEADBEEF");
    assert!(Dynamic::<[u8]>::try_from_hex("zz").is_err());
}

#[cfg(feature = "encoding-base32")]
#[test]
fn base32_round_trips_through_a_slice() {
    use secure_gate::ToBase32;
    let s: Dynamic<[u8]> = Dynamic::new_with(4, |b| b.fill(0xAB));
    let back = Dynamic::<[u8]>::try_from_base32(&s.to_base32()).unwrap();
    assert_eq!(back.expose_secret(), s.expose_secret());
}

#[cfg(feature = "encoding-base64")]
#[test]
fn base64url_round_trips_through_a_slice() {
    use secure_gate::ToBase64Url;
    let s: Dynamic<[u8]> = Dynamic::new_with(7, |b| b.fill(0x5A));
    let back = Dynamic::<[u8]>::try_from_base64url(&s.to_base64url()).unwrap();
    assert_eq!(back.expose_secret(), s.expose_secret());
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn bech32_and_bech32m_round_trip_through_a_slice() {
    use secure_gate::{Case, ToBech32, ToBech32m};
    let s: Dynamic<[u8]> = Dynamic::new_with(16, |b| b.fill(0x11));
    let a = s.try_to_bech32("key", Case::Lower).unwrap();
    let m = s.try_to_bech32m("key", Case::Lower).unwrap();
    let back_a = Dynamic::<[u8]>::try_from_bech32(&a, "key").unwrap();
    let back_m = Dynamic::<[u8]>::try_from_bech32m(&m, "key").unwrap();
    assert_eq!(back_a.expose_secret(), s.expose_secret());
    assert_eq!(back_m.expose_secret(), s.expose_secret());
}
