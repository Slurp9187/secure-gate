//! macros_suite/dynamic_generic.rs — dynamic_generic_alias macro tests

#[cfg(feature = "alloc")]
use secure_gate::{dynamic_generic_alias, ExposeSecret};

#[cfg(feature = "alloc")]
dynamic_generic_alias!(GenericBox);

#[cfg(feature = "alloc")]
#[test]
fn dynamic_generic_alias_vec() {
    let val: GenericBox<Vec<u8>> = vec![1u8, 2, 3].into();
    val.with_secret(|s| assert_eq!(s, &[1u8, 2, 3]));
}

#[cfg(feature = "alloc")]
#[test]
fn dynamic_generic_alias_string() {
    let val: GenericBox<String> = "secret".to_string().into();
    val.with_secret(|s| assert_eq!(s, "secret"));
}
