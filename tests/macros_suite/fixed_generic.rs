//! macros_suite/fixed_generic.rs — fixed_generic_alias macro tests

use secure_gate::{fixed_generic_alias, ExposeSecret};

fixed_generic_alias!(GenericBuffer);

#[test]
fn fixed_generic_alias_basic() {
    let key: GenericBuffer<16> = [0xAAu8; 16].into();
    key.with_secret(|s| assert_eq!(s, &[0xAAu8; 16]));
    assert_eq!(core::mem::size_of::<GenericBuffer<32>>(), 32);
}

#[test]
fn fixed_generic_alias_n_zero_accepted() {
    // N=0 is not rejected at compile time for generic aliases (unlike fixed_alias!).
    // Zero-byte Fixed<[u8; 0]> has no cryptographic utility; this test documents the behavior.
    let _: GenericBuffer<0> = GenericBuffer::new([]);
}
