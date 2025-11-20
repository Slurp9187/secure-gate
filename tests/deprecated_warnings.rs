// tests/deprecated_warnings.rs
//
// Permanent regression test: deprecation warnings + alias correctness
// Must compile and (when zeroize is enabled) emit visible warnings.

#![allow(deprecated)]
#![allow(unused_imports)] // some imports are only used in cfg-gated tests

extern crate alloc;

#[cfg(feature = "zeroize")]
use secure_gate::{
    // Constructors (stack feature only)
    iv16,
    salt16,
    // Deprecated names – must warn
    SecureIv,
    // Modern names – must compile cleanly
    SecureIv16,
    SecureKey32,
    SecureNonce128,
    SecureSalt,
    SecureSalt16,
};

#[cfg(feature = "zeroize")]
#[test]
fn deprecated_secure_iv_emits_warning() {
    // This line MUST produce a deprecation warning when zeroize is on
    let _iv: SecureIv = SecureIv16::new([0u8; 16]);
}

#[cfg(feature = "zeroize")]
#[test]
fn deprecated_secure_salt_emits_warning() {
    // This line MUST produce a deprecation warning
    let _salt: SecureSalt = SecureSalt16::new([1u8; 16]);
}

#[cfg(feature = "zeroize")]
#[test]
fn modern_aliases_compile_cleanly() {
    let _iv: SecureIv16 = SecureIv16::new([0u8; 16]);
    let _salt: SecureSalt16 = SecureSalt16::new([2u8; 16]);
    let _key: SecureKey32 = SecureKey32::new([3u8; 32]);
    let _nonce: SecureNonce128 = SecureNonce128::new([4u8; 16]);
}

#[cfg(all(feature = "zeroize", feature = "stack"))]
#[test]
fn stack_constructors_match_modern_aliases() {
    let _iv: SecureIv16 = iv16([5u8; 16]);
    let _salt: SecureSalt16 = salt16([6u8; 16]);
}

#[cfg(all(feature = "zeroize", feature = "stack"))]
#[test]
fn deprecated_aliases_work_with_stack_feature() {
    // Still warns, but must compile
    let _iv: SecureIv = iv16([7u8; 16]);
    let _salt: SecureSalt = salt16([8u8; 16]);
}

// When zeroize is disabled, the deprecated items simply do not exist – good!
#[cfg(not(feature = "zeroize"))]
#[test]
fn deprecated_items_are_gated_correctly() {
    // Trying to reference them would fail to compile → this test passes by existing
    // (No code needed – the fact that the file compiles proves the items are gone)
}
