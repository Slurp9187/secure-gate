// tests/macros_visibility_tests.rs
// Exhaustive visibility testing for all secure-gate macros

#![cfg(test)]
#![cfg(feature = "rand")]
use secure_gate::fixed_alias_rng;

use secure_gate::{dynamic_alias, fixed_alias};

// ──────────────────────────────────────────────────────────────
// Test visibility inside a nested module (so `super` is valid)
// ──────────────────────────────────────────────────────────────
mod visibility_module {
    use super::*;

    // These are only visible to parent (`super`) or crate
    fixed_alias!(pub(crate) CrateKey, 32);
    fixed_alias!(pub(in super) ParentKey, 16);
    fixed_alias!(pub(in crate) CratePathKey, 48);

    // Private to this module
    fixed_alias!(ModulePrivateKey, 64);

    #[test]
    fn can_use_all_defined_keys() {
        let _c: CrateKey = [0u8; 32].into();
        let _p: ParentKey = [0u8; 16].into();
        let _cp: CratePathKey = [0u8; 48].into();
        let _m: ModulePrivateKey = [0u8; 64].into();

        assert_eq!(_c.len(), 32);
        assert_eq!(_p.len(), 16);
    }
}

// ──────────────────────────────────────────────────────────────
// From the parent scope, we can access `pub(in super)` and `pub(crate)`
// ──────────────────────────────────────────────────────────────
#[test]
fn parent_can_access_child_pub_in_super() {
    // This compiles — we are the `super` of `visibility_module`
    let _k: visibility_module::ParentKey = [0u8; 16].into();
    let _c: visibility_module::CrateKey = [0u8; 32].into();
    let _cp: visibility_module::CratePathKey = [0u8; 48].into();

    // This would NOT compile:
    // let _m: visibility_module::ModulePrivateKey = ...; // private → inaccessible
}

// ──────────────────────────────────────────────────────────────
// Test default (pub) and private visibility in root
// ──────────────────────────────────────────────────────────────
fixed_alias!(pub GlobalKey, 96);
fixed_alias!(RootPrivateKey, 128); // no pub → private to this file

#[test]
fn root_visibility_works() {
    let _g: GlobalKey = [0u8; 96].into();
    let _r: RootPrivateKey = [0u8; 128].into();
}

// ──────────────────────────────────────────────────────────────
// RNG and Dynamic aliases with visibility
// ──────────────────────────────────────────────────────────────
#[cfg(feature = "rand")]
mod rng_vis {
    use super::*;

    fixed_alias_rng!(pub(crate) CrateRngKey, 32);
    fixed_alias_rng!(pub(in super) ParentRngKey, 24);

    #[test]
    fn rng_visibility_works() {
        let _k = CrateRngKey::generate();
        let _n = ParentRngKey::generate();
        assert_eq!(_k.len(), 32);
        assert_eq!(_n.len(), 24);
    }
}

#[cfg(feature = "rand")]
#[test]
fn parent_can_access_rng_pub_in_super() {
    let _n = rng_vis::ParentRngKey::generate();
    let _k = rng_vis::CrateRngKey::generate();
    assert_eq!(_n.len(), 24);
}

mod dynamic_vis {
    use super::*;

    dynamic_alias!(pub(crate) CratePass, String);
    dynamic_alias!(pub(in super) ParentToken, Vec<u8>);

    #[test]
    fn dynamic_visibility_works() {
        let _p: CratePass = "secret".into();
        let _t: ParentToken = vec![9; 10].into();
        assert_eq!(_p.len(), 6);
        assert_eq!(_t.len(), 10);
    }
}

#[test]
fn parent_can_access_dynamic_pub_in_super() {
    let _t: dynamic_vis::ParentToken = vec![1].into();
    let _p: dynamic_vis::CratePass = "ok".into();
}
