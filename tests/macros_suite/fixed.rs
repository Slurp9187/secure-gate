//! macros_suite/fixed.rs — fixed_alias macro tests

use secure_gate::{fixed_alias, RevealSecret};

fixed_alias!(LocalFixed32, 32);

#[test]
fn fixed_alias_basics() {
    let key: LocalFixed32 = [7u8; 32].into();
    key.with_secret(|s| assert_eq!(s, &[7u8; 32]));
}
