//! macros_suite/dynamic.rs — dynamic_alias macro tests

#[cfg(feature = "alloc")]
use secure_gate::{dynamic_alias, ExposeSecret};

#[cfg(feature = "alloc")]
dynamic_alias!(LocalDynVec, Vec<u8>);

#[cfg(feature = "alloc")]
#[test]
fn dynamic_alias_basics() {
    let val: LocalDynVec = vec![1u8, 2, 3].into();
    val.with_secret(|s| assert_eq!(s, &[1, 2, 3]));
}
