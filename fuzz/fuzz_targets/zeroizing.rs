// fuzz/fuzz_targets/zeroizing.rs
//
// Fuzz target for all zeroizing paths — FixedZeroizing, DynamicZeroizing, and drops
// (v0.5.0 – use re-exports only)
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use secrecy::ExposeSecret;
use secure_gate_fuzz::arbitrary::{
    FuzzDynamicString, FuzzDynamicVec, FuzzDynamicZeroizingString, FuzzDynamicZeroizingVec,
    FuzzFixed32, FuzzFixedZeroizing32,
}; // Private to fuzz — OK

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);

    let _fixed_32 = match FuzzFixed32::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };
    let fixed_zero_32 = match FuzzFixedZeroizing32::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };
    let _dyn_vec = match FuzzDynamicVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };
    let _dyn_str = match FuzzDynamicString::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };
    let dyn_zero_vec = match FuzzDynamicZeroizingVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };
    let dyn_zero_str = match FuzzDynamicZeroizingString::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    // ---------- FixedZeroizing ----------
    let _ = &*fixed_zero_32;
    drop(fixed_zero_32);

    // ---------- DynamicZeroizing<Vec<u8>> ----------
    let _ = dyn_zero_vec.expose_secret().len();
    drop(dyn_zero_vec);

    // ---------- DynamicZeroizing<String> ----------
    let _ = dyn_zero_str.expose_secret().len();
    drop(dyn_zero_str);
});
