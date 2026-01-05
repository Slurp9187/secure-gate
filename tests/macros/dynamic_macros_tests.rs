// secure-gate/tests/macros/dynamic_macros_tests.rs
// Tests for dynamic (heap) alias macros.

#![cfg(test)]

use secure_gate::dynamic_alias;

// ──────────────────────────────────────────────────────────────
// Dynamic (heap) alias
// ──────────────────────────────────────────────────────────────
#[test]
fn dynamic_alias_basics() {
    dynamic_alias!(MyPass, String);
    dynamic_alias!(MyToken, Vec<u8>);

    let p: MyPass = "hunter2".into();
    assert_eq!(p.expose_secret(), "hunter2");

    let t: MyToken = vec![1, 2, 3].into();
    assert_eq!(t.expose_secret(), &[1, 2, 3]);
}

// ──────────────────────────────────────────────────────────────
// Visibility tests for dynamic aliases
// ──────────────────────────────────────────────────────────────
mod vis {
    use super::*;

    dynamic_alias!(pub(crate) CratePass, String);
    dynamic_alias!(pub(in super) ParentToken, Vec<u8>);

    #[test]
    fn visibility_works() {
        let _p: CratePass = "secret".into();
        let _t: ParentToken = vec![9; 10].into();
        assert_eq!(_p.len(), 6);
        assert_eq!(_t.len(), 10);
    }
}

#[test]
fn parent_can_access_pub_in_super() {
    let _t: vis::ParentToken = vec![1].into();
    let _p: vis::CratePass = "ok".into();
}

dynamic_alias!(pub GlobalPass, String);
dynamic_alias!(RootPrivateToken, Vec<u8>); // private

#[test]
fn root_visibility_works() {
    let _g: GlobalPass = "global".into();
    let _r: RootPrivateToken = vec![0; 10].into();
}
