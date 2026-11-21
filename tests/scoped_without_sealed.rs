//! `RevealScoped` is usable without the `sealed` feature: a library can bound on it and
//! accept plain secrets today, sealed ones when its caller enables `sealed`.

use secure_gate::Fixed;
use secure_gate::scoped::RevealScoped;

fn first_byte<S: RevealScoped<Inner = [u8; 4]>>(s: &S) -> u8 {
    s.with_secret(|b| b[0])
}

#[test]
fn a_plain_secret_is_reveal_scoped() {
    assert_eq!(first_byte(&Fixed::new([7u8, 0, 0, 0])), 7);
}

#[cfg(feature = "alloc")]
#[test]
fn a_dynamic_secret_is_reveal_scoped() {
    let s = secure_gate::Dynamic::<String>::new(String::from("abc"));
    assert_eq!(RevealScoped::with_secret(&s, |t| t.len()), 3);
}
