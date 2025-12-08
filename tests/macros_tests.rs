// ==========================================================================
// tests/macro_tests.rs
// ==========================================================================
// Comprehensive testing for all macros

#![cfg(test)]

use secure_gate::{dynamic_alias, fixed_alias};

#[cfg(feature = "rand")]
use secure_gate::{
    fixed_alias_rng,
    rng::{DynamicRng, FixedRng},
};

// ──────────────────────────────────────────────────────────────
// Basic macro functionality
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_alias_basics() {
    fixed_alias!(MyKey, 32);

    let k: MyKey = [0u8; 32].into();
    assert_eq!(k.len(), 32);
    assert_eq!(k.expose_secret().len(), 32);
}

#[test]
fn dynamic_alias_basics() {
    dynamic_alias!(MyPass, String);
    dynamic_alias!(MyToken, Vec<u8>);

    let p: MyPass = "hunter2".into();
    assert_eq!(p.expose_secret(), "hunter2");

    let t: MyToken = vec![1, 2, 3].into();
    assert_eq!(t.expose_secret(), &[1, 2, 3]);
}

#[cfg(feature = "rand")]
#[test]
fn fixed_alias_rng_basics() {
    fixed_alias_rng!(Aes256Key, 32);
    fixed_alias_rng!(Nonce, 24);

    let k1 = Aes256Key::generate();
    let k2 = Aes256Key::generate();
    assert_ne!(k1.expose_secret(), k2.expose_secret());
    assert_eq!(k1.len(), 32);

    let n1 = Nonce::generate();
    assert_eq!(n1.len(), 24);
    assert_ne!(*n1.expose_secret(), [0u8; 24]);
}

#[cfg(feature = "rand")]
#[test]
fn raw_rng_types_work() {
    // Fixed-size
    let a = FixedRng::<16>::generate();
    let b = FixedRng::<16>::generate();
    assert_ne!(a.expose_secret(), b.expose_secret());

    // Dynamic — length must be specified
    let c = DynamicRng::generate(64);
    assert_eq!(c.expose_secret().len(), 64);

    // Using a type alias (preferred style)
    type MyToken = DynamicRng;
    let d = MyToken::generate(128);
    assert_eq!(d.expose_secret().len(), 128);
}

#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn random_hex_via_alias() {
    fixed_alias_rng!(HexKey, 32);

    let hex = HexKey::random_hex();

    assert_eq!(hex.expose_secret().len(), 64);
    assert!(hex.expose_secret().chars().all(|c| c.is_ascii_hexdigit()));
    assert!(hex.expose_secret().chars().all(|c| !c.is_uppercase()));

    let bytes = hex.to_bytes();
    assert_eq!(bytes.len(), 32);
}

#[cfg(feature = "conversions")]
#[test]
fn hexstring_new_rejects_invalid() {
    use secure_gate::HexString;

    let s = "invalid hex".to_string(); // odd length
    let err = HexString::new(s).unwrap_err();
    assert_eq!(err, "invalid hex string");

    let s = "g".to_string(); // invalid digit
    let err = HexString::new(s).unwrap_err();
    assert_eq!(err, "invalid hex string");
}

#[cfg(feature = "conversions")]
#[test]
fn hexstring_new_in_place_lowercase() {
    use secure_gate::HexString;

    let s = "DEADBEEF".to_string();
    let hex = HexString::new(s).unwrap();
    assert_eq!(hex.expose_secret(), "deadbeef");
    assert_eq!(hex.byte_len(), 4);
}

// ──────────────────────────────────────────────────────────────
// Visibility testing
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

#[test]
fn parent_can_access_child_pub_in_super() {
    // This compiles — we are the `super` of `visibility_module`
    let _k: visibility_module::ParentKey = [0u8; 16].into();
    let _c: visibility_module::CrateKey = [0u8; 32].into();
    let _cp: visibility_module::CratePathKey = [0u8; 48].into();

    // This would NOT compile:
    // let _m: visibility_module::ModulePrivateKey = ...; // private → inaccessible
}

fixed_alias!(pub GlobalKey, 96);
fixed_alias!(RootPrivateKey, 128); // no pub → private to this file

#[test]
fn root_visibility_works() {
    let _g: GlobalKey = [0u8; 96].into();
    let _r: RootPrivateKey = [0u8; 128].into();
}

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


// ──────────────────────────────────────────────────────────────
// Edge case: Zero-sized arrays
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_alias_zero_size() {
    fixed_alias!(ZeroKey, 0);
    
    let k: ZeroKey = [].into();
    assert_eq!(k.len(), 0);
    assert!(k.is_empty());
    assert_eq!(k.expose_secret().len(), 0);
}

#[test]
fn fixed_alias_single_byte() {
    fixed_alias!(SingleByte, 1);
    
    let k: SingleByte = [42u8].into();
    assert_eq!(k.len(), 1);
    assert_eq!(*k.expose_secret(), [42u8]);
}

// ──────────────────────────────────────────────────────────────
// Edge case: Very large sizes
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_alias_large_size() {
    fixed_alias!(LargeKey, 4096);
    
    let k: LargeKey = [0u8; 4096].into();
    assert_eq!(k.len(), 4096);
    assert_eq!(k.expose_secret().len(), 4096);
}

// ──────────────────────────────────────────────────────────────
// Edge case: Different visibility modifiers
// ──────────────────────────────────────────────────────────────

mod visibility_edge_cases {
    use super::*;
    
    // Test all visibility variants
    fixed_alias!(pub PublicKey, 32);
    fixed_alias!(pub(crate) CrateKey, 32);
    fixed_alias!(pub(super) SuperKey, 32);
    fixed_alias!(PrivateKey, 32); // No visibility = private
    
    #[test]
    fn all_visibility_variants_work() {
        let _p: PublicKey = [0u8; 32].into();
        let _c: CrateKey = [0u8; 32].into();
        let _s: SuperKey = [0u8; 32].into();
        let _pr: PrivateKey = [0u8; 32].into();
    }
}

// ──────────────────────────────────────────────────────────────
// Edge case: Generic aliases (fixed_generic_alias)
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_generic_alias_with_doc() {
    use secure_gate::fixed_generic_alias;
    
    fixed_generic_alias!(pub GenericKey, "A generic secure key");
    
    let k: GenericKey<32> = [0u8; 32].into();
    assert_eq!(k.len(), 32);
    
    let k2: GenericKey<64> = [0u8; 64].into();
    assert_eq!(k2.len(), 64);
}

#[test]
fn fixed_generic_alias_without_doc() {
    use secure_gate::fixed_generic_alias;
    
    fixed_generic_alias!(pub Buffer);
    
    let b: Buffer<16> = [0u8; 16].into();
    assert_eq!(b.len(), 16);
    
    let b2: Buffer<128> = [0u8; 128].into();
    assert_eq!(b2.len(), 128);
}

#[test]
fn fixed_generic_alias_private() {
    use secure_gate::fixed_generic_alias;
    
    fixed_generic_alias!(PrivateBuffer);
    
    let b: PrivateBuffer<8> = [0u8; 8].into();
    assert_eq!(b.len(), 8);
}

// ──────────────────────────────────────────────────────────────
// Edge case: Generic aliases (dynamic_generic_alias)
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_generic_alias_with_doc() {
    use secure_gate::dynamic_generic_alias;
    
    dynamic_generic_alias!(pub SecureString, String, "A secure string type");
    
    let s: SecureString = "test".into();
    assert_eq!(s.expose_secret(), "test");
}

#[test]
fn dynamic_generic_alias_without_doc() {
    use secure_gate::dynamic_generic_alias;
    
    dynamic_generic_alias!(pub SecureVec, Vec<u8>);
    
    let v: SecureVec = vec![1, 2, 3].into();
    assert_eq!(v.expose_secret(), &[1, 2, 3]);
}

#[test]
fn dynamic_generic_alias_different_types() {
    use secure_gate::dynamic_generic_alias;
    
    dynamic_generic_alias!(pub MyString, String);
    dynamic_generic_alias!(pub MyVec, Vec<u8>);
    
    let s: MyString = "hello".into();
    let v: MyVec = vec![42u8; 10].into();
    
    assert_eq!(s.expose_secret(), "hello");
    assert_eq!(v.expose_secret().len(), 10);
}

// ──────────────────────────────────────────────────────────────
// Edge case: RNG aliases with different sizes
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "rand")]
#[test]
fn fixed_alias_rng_zero_size() {
    fixed_alias_rng!(ZeroRng, 0);
    
    let r = ZeroRng::generate();
    assert_eq!(r.len(), 0);
    assert!(r.is_empty());
}

#[cfg(feature = "rand")]
#[test]
fn fixed_alias_rng_single_byte() {
    fixed_alias_rng!(SingleRng, 1);
    
    let r = SingleRng::generate();
    assert_eq!(r.len(), 1);
    assert!(*r.expose_secret() != [0u8]);
}

#[cfg(feature = "rand")]
#[test]
fn fixed_alias_rng_large_size() {
    fixed_alias_rng!(LargeRng, 1024);
    
    let r = LargeRng::generate();
    assert_eq!(r.len(), 1024);
    // Verify it's not all zeros
    assert!(!r.expose_secret().iter().all(|&b| b == 0));
}

// ──────────────────────────────────────────────────────────────
// Edge case: Dynamic aliases with different types
// ──────────────────────────────────────────────────────────────

#[test]
fn dynamic_alias_string() {
    dynamic_alias!(MyPassword, String);
    
    let p: MyPassword = "secret123".into();
    assert_eq!(p.expose_secret(), "secret123");
    assert_eq!(p.len(), 9);
}

#[test]
fn dynamic_alias_vec_u8() {
    dynamic_alias!(MyToken, Vec<u8>);
    
    let t: MyToken = vec![1, 2, 3, 4, 5].into();
    assert_eq!(t.expose_secret(), &[1, 2, 3, 4, 5]);
    assert_eq!(t.len(), 5);
}

#[test]
fn dynamic_alias_empty() {
    dynamic_alias!(EmptyString, String);
    dynamic_alias!(EmptyVec, Vec<u8>);
    
    let s: EmptyString = "".into();
    let v: EmptyVec = vec![].into();
    
    assert!(s.is_empty());
    assert!(v.is_empty());
}

// ──────────────────────────────────────────────────────────────
// Edge case: Multiple aliases in same scope
// ──────────────────────────────────────────────────────────────

#[test]
fn multiple_aliases_same_scope() {
    fixed_alias!(KeyA, 32);
    fixed_alias!(KeyB, 64);
    fixed_alias!(KeyC, 128);
    
    let a: KeyA = [0u8; 32].into();
    let b: KeyB = [0u8; 64].into();
    let c: KeyC = [0u8; 128].into();
    
    assert_eq!(a.len(), 32);
    assert_eq!(b.len(), 64);
    assert_eq!(c.len(), 128);
}

#[test]
fn multiple_dynamic_aliases_same_scope() {
    dynamic_alias!(Pass1, String);
    dynamic_alias!(Pass2, String);
    dynamic_alias!(Token1, Vec<u8>);
    dynamic_alias!(Token2, Vec<u8>);
    
    let p1: Pass1 = "pass1".into();
    let p2: Pass2 = "pass2".into();
    let t1: Token1 = vec![1].into();
    let t2: Token2 = vec![2].into();
    
    assert_eq!(p1.expose_secret(), "pass1");
    assert_eq!(p2.expose_secret(), "pass2");
    assert_eq!(t1.expose_secret(), &[1]);
    assert_eq!(t2.expose_secret(), &[2]);
}

// ──────────────────────────────────────────────────────────────
// Edge case: Nested modules with aliases
// ──────────────────────────────────────────────────────────────

mod nested_level_1 {
    pub mod nested_level_2 {
        use secure_gate::fixed_alias;
        
        fixed_alias!(pub NestedKey, 16);
        
        #[test]
        fn nested_key_works() {
            let k: NestedKey = [0u8; 16].into();
            assert_eq!(k.len(), 16);
        }
    }
    
    #[test]
    fn can_access_nested_key() {
        let k: nested_level_2::NestedKey = [0u8; 16].into();
        assert_eq!(k.len(), 16);
    }
}

// ──────────────────────────────────────────────────────────────
// Edge case: Type name edge cases
// ──────────────────────────────────────────────────────────────

#[test]
fn type_name_with_underscores() {
    #[allow(non_camel_case_types)]
    type My_Special_Key = secure_gate::Fixed<[u8; 32]>;
    
    let k: My_Special_Key = [0u8; 32].into();
    assert_eq!(k.len(), 32);
}

#[test]
fn type_name_camel_case() {
    fixed_alias!(MyCamelCaseKey, 32);
    
    let k: MyCamelCaseKey = [0u8; 32].into();
    assert_eq!(k.len(), 32);
}

// ──────────────────────────────────────────────────────────────
// Edge case: All methods work on aliases
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_alias_all_methods() {
    fixed_alias!(TestKey, 32);
    
    let mut k: TestKey = [42u8; 32].into();
    
    // Test all methods
    assert_eq!(k.len(), 32);
    assert!(!k.is_empty());
    
    let bytes = k.expose_secret();
    assert_eq!(bytes.len(), 32);
    assert_eq!(bytes[0], 42);
    
    let bytes_mut = k.expose_secret_mut();
    bytes_mut[0] = 99;
    assert_eq!(k.expose_secret()[0], 99);
}

#[test]
fn dynamic_alias_all_methods() {
    dynamic_alias!(TestString, String);
    
    let mut s: TestString = "hello".into();
    
    assert_eq!(s.len(), 5);
    assert!(!s.is_empty());
    
    let str_ref = s.expose_secret();
    assert_eq!(str_ref, "hello");
    
    let str_mut = s.expose_secret_mut();
    str_mut.push('!');
    assert_eq!(s.expose_secret(), "hello!");
}

// ──────────────────────────────────────────────────────────────
// Edge case: Conversions work with aliases
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "conversions")]
#[test]
fn fixed_alias_conversions() {
    use secure_gate::SecureConversionsExt;
    
    fixed_alias!(ConvKey, 32);
    
    let k: ConvKey = [0x42u8; 32].into();
    
    let hex = k.expose_secret().to_hex();
    assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
    
    let b64 = k.expose_secret().to_base64url();
    assert!(!b64.is_empty());
    
    let k2: ConvKey = [0x42u8; 32].into();
    assert!(k.expose_secret().ct_eq(k2.expose_secret()));
}

// ──────────────────────────────────────────────────────────────
// Edge case: RNG conversions work with aliases
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "rand")]
#[test]
fn fixed_alias_rng_conversions() {
    fixed_alias_rng!(RngKey, 32);
    
    let rng = RngKey::generate();
    let fixed = rng.into_inner();
    
    assert_eq!(fixed.len(), 32);
    assert_eq!(fixed.expose_secret().len(), 32);
}

#[cfg(feature = "rand")]
#[test]
fn fixed_alias_rng_from_trait() {
    use secure_gate::Fixed;
    
    fixed_alias_rng!(RngKey, 32);
    
    let rng = RngKey::generate();
    let fixed: Fixed<[u8; 32]> = rng.into();
    
    assert_eq!(fixed.len(), 32);
}

#[cfg(feature = "rand")]
#[test]
fn fixed_alias_rng_all_visibility() {
    mod rng_vis {
        use secure_gate::fixed_alias_rng;
        
        fixed_alias_rng!(pub PublicRng, 32);
        fixed_alias_rng!(pub(crate) CrateRng, 32);
        fixed_alias_rng!(pub(super) SuperRng, 32);
        fixed_alias_rng!(PrivateRng, 32);
        
        #[allow(dead_code)]
        fn all_rng_visibility_works() {
            let _p = PublicRng::generate();
            let _c = CrateRng::generate();
            let _s = SuperRng::generate();
            let _pr = PrivateRng::generate();
        }
    }
    
    let _s = rng_vis::SuperRng::generate();
    let _c = rng_vis::CrateRng::generate();
    let _p = rng_vis::PublicRng::generate();
}

#[cfg(feature = "rand")]
#[test]
fn fixed_alias_rng_multiple_sizes() {
    fixed_alias_rng!(Rng8, 8);
    fixed_alias_rng!(Rng16, 16);
    fixed_alias_rng!(Rng32, 32);
    fixed_alias_rng!(Rng64, 64);
    fixed_alias_rng!(Rng128, 128);
    
    let r8 = Rng8::generate();
    let r16 = Rng16::generate();
    let r32 = Rng32::generate();
    let r64 = Rng64::generate();
    let r128 = Rng128::generate();
    
    assert_eq!(r8.len(), 8);
    assert_eq!(r16.len(), 16);
    assert_eq!(r32.len(), 32);
    assert_eq!(r64.len(), 64);
    assert_eq!(r128.len(), 128);
}

// ──────────────────────────────────────────────────────────────
// Edge case: Generic alias with different const parameters
// ──────────────────────────────────────────────────────────────

#[test]
fn fixed_generic_alias_multiple_sizes() {
    use secure_gate::fixed_generic_alias;
    
    fixed_generic_alias!(pub FlexKey);
    
    // Test with many different sizes
    let k8: FlexKey<8> = [0u8; 8].into();
    let k16: FlexKey<16> = [0u8; 16].into();
    let k32: FlexKey<32> = [0u8; 32].into();
    let k64: FlexKey<64> = [0u8; 64].into();
    let k128: FlexKey<128> = [0u8; 128].into();
    
    assert_eq!(k8.len(), 8);
    assert_eq!(k16.len(), 16);
    assert_eq!(k32.len(), 32);
    assert_eq!(k64.len(), 64);
    assert_eq!(k128.len(), 128);
}

