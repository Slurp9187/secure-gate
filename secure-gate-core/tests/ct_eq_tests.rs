//! Constant-time equality tests (`ct-eq` feature).

#[cfg(feature = "ct-eq")]
use secure_gate::ConstantTimeEq;
#[cfg(feature = "alloc")]
use secure_gate::Dynamic;
#[cfg(all(feature = "ct-eq", feature = "alloc"))]
use secure_gate::Fixed;

#[cfg(feature = "ct-eq")]
#[test]
fn slice_ct_eq_basic() {
    assert!([1u8, 2, 3].as_slice().ct_eq(&[1, 2, 3]));
    assert!(![1u8, 2, 3].as_slice().ct_eq(&[1, 2, 4]));
    assert!(![1u8, 2, 3].as_slice().ct_eq(&[1, 2]));
    assert!(![1u8, 2].as_slice().ct_eq(&[1, 2, 3]));
}

#[cfg(feature = "ct-eq")]
#[test]
fn array_ct_eq_basic() {
    assert!([1u8, 2, 3].ct_eq(&[1, 2, 3]));
    assert!(![1u8, 2, 3].ct_eq(&[1, 2, 4]));
}

#[cfg(all(feature = "ct-eq", feature = "alloc"))]
#[test]
fn wrapper_ct_eq_dynamic_and_fixed() {
    let fixed1 = Fixed::new([1u8, 2, 3]);
    let fixed2 = Fixed::new([1u8, 2, 3]);
    let fixed3 = Fixed::new([1u8, 2, 4]);
    assert!(fixed1.ct_eq(&fixed2));
    assert!(!fixed1.ct_eq(&fixed3));

    let dyn1: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    let dyn2: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    let dyn3: Dynamic<Vec<u8>> = vec![1, 2, 4].into();
    assert!(dyn1.ct_eq(&dyn2));
    assert!(!dyn1.ct_eq(&dyn3));
}

#[cfg(all(feature = "ct-eq", feature = "alloc"))]
#[test]
fn string_ct_eq_basic() {
    let a = String::from("hello");
    let b = String::from("hello");
    let c = String::from("world");
    let d = String::from("hel");
    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
    assert!(!a.ct_eq(&d));
}

#[cfg(all(feature = "ct-eq", feature = "alloc"))]
#[test]
fn wrapper_ct_eq_dynamic_string() {
    let d1: Dynamic<String> = "secret".into();
    let d2: Dynamic<String> = "secret".into();
    let d3: Dynamic<String> = "differ".into();
    let d4: Dynamic<String> = "short".into();
    assert!(d1.ct_eq(&d2));
    assert!(!d1.ct_eq(&d3));
    assert!(!d1.ct_eq(&d4));
}

#[cfg(all(not(feature = "ct-eq"), feature = "alloc"))]
#[test]
fn manual_comparison_without_ct_eq_feature() {
    // This demonstrates how secrets can be compared when the `ct-eq` feature is
    // disabled, but the comparison is NON-constant-time — `assert_eq!` on exposed
    // slices uses a short-circuit equality check that leaks timing information.
    // For security-sensitive equality always enable `ct-eq` and use `ConstantTimeEq`.
    use secure_gate::RevealSecret;
    let dyn1: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    let dyn2: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    dyn1.with_secret(|a| dyn2.with_secret(|b| assert_eq!(a, b)));
}
