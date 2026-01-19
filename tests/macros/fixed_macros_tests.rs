// secure-gate/tests/macros/fixed_macros_tests.rs
// Tests for fixed-size alias macros and their visibility.

#![cfg(test)]

use secure_gate::fixed_alias;
#[cfg(feature = "rand")]
use secure_gate::fixed_alias_random;
use secure_gate::ExposeSecret;

// ──────────────────────────────────────────────────────────────
// Basic fixed-size alias (no rand)
// ──────────────────────────────────────────────────────────────
#[test]
fn fixed_alias_basics() {
    fixed_alias!(MyKey, 32);

    let k: MyKey = [0u8; 32].into();
    assert_eq!(k.len(), 32);
    assert_eq!(k.expose_secret().len(), 32);
}

#[test]
fn non_zero_size_validation() {
    // Valid minimal size
    fixed_alias!(MinimalKey, 1);
    let k: MinimalKey = [42u8].into();
    assert_eq!(k.len(), 1);

    // Compile-fail test: Uncomment to verify (should fail build)
    // fixed_alias!(ZeroKey, 0);  // Expected: Compile error
}

// ──────────────────────────────────────────────────────────────
// Visibility tests for fixed aliases
// ──────────────────────────────────────────────────────────────
mod vis {
    use super::*;

    // These are only visible to parent (`super`) or crate
    fixed_alias!(pub(crate) CrateKey, 32);
    fixed_alias!(pub(in super) ParentKey, 16);
    fixed_alias!(pub(in crate) CratePathKey, 48);

    // Private to this module
    fixed_alias!(ModulePrivateKey, 64);

    #[test]
    fn visibility_works() {
        let _c: CrateKey = [0u8; 32].into();
        let _p: ParentKey = [0u8; 16].into();
        let _cp: CratePathKey = [0u8; 48].into();
        let _m: ModulePrivateKey = [0u8; 64].into();

        assert_eq!(_c.len(), 32);
        assert_eq!(_p.len(), 16);
    }
}

#[test]
fn parent_can_access_pub_in_super() {
    // This compiles — we are the `super` of `vis`
    let _k: vis::ParentKey = [0u8; 16].into();
    let _c: vis::CrateKey = [0u8; 32].into();
    let _cp: vis::CratePathKey = [0u8; 48].into();

    // This would NOT compile:
    // let _m: vis::ModulePrivateKey = ...; // private → inaccessible
}

fixed_alias!(pub GlobalKey, 96);
fixed_alias!(RootPrivateKey, 128); // no pub → private to this file

#[test]
fn root_visibility_works() {
    let _g: GlobalKey = [0u8; 96].into();
    let _r: RootPrivateKey = [0u8; 128].into();
}

// ──────────────────────────────────────────────────────────────
// RNG visibility tests for fixed aliases
// ──────────────────────────────────────────────────────────────
#[cfg(feature = "rand")]
mod rng_vis {
    use super::*;

    fixed_alias_random!(pub(crate) CrateRngKey, 32);
    fixed_alias_random!(pub(in super) ParentRngKey, 24);

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

// === Alias type distinction ===
#[test]
fn fixed_aliases_distinct_types() {
    fixed_alias!(TypeA, 32);
    fixed_alias!(TypeB, 32);

    let _a: TypeA = [0u8; 32].into();
    // let _wrong: TypeB = a; // Must not compile — different nominal types
    // Compile-fail guard: ensures semantic types don't coerce
}

#[test]
fn fixed_alias_with_custom_doc() {
    fixed_alias!(pub KeyWithDoc, 32, "Custom documentation for key");

    let k: KeyWithDoc = [0u8; 32].into();
    assert_eq!(k.len(), 32);
}

#[cfg(feature = "rand")]
#[test]
fn fixed_alias_random_with_custom_doc() {
    fixed_alias_random!(pub RngKeyWithDoc, 32, "Custom documentation for random key");

    let k = RngKeyWithDoc::generate();
    assert_eq!(k.len(), 32);
}

#[cfg(feature = "rand")]
#[test]
fn rng_aliases_distinct_types() {
    fixed_alias_random!(RngTypeA, 32);
    fixed_alias_random!(RngTypeB, 32);

    let _a = RngTypeA::generate();
    // let _wrong: RngTypeB = a; // Must not compile
}
