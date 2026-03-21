// fuzz/fuzz_targets/ct_eq.rs
//
// Constant-time equality fuzz target for secure-gate.
//
// Tests `ct_eq` for `Fixed<[u8;32]>` and `Dynamic<Vec<u8>>`.
// Verifies reflexivity, symmetry, and correctness.
//
// Security invariants checked:
//   - x.ct_eq(&x) == true          (reflexivity)
//   - x.ct_eq(&y) == y.ct_eq(&x)   (symmetry)
//   - ct_eq(&a, &b) matches byte equality
//   - Empty/single-byte edge cases don't panic
//
// Corpus seed hints (paste into fuzz/corpus/ct_eq/):
//   \x00\x00\x00\x00 (32 zeros repeated)
//   \xff\xff\xff\xff (32 0xFF repeated)
//   \x00\x01\x02...  (sequential bytes)
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{ConstantTimeEq, Dynamic, RevealSecret};
use secure_gate_fuzz::arbitrary::{FuzzDynamicVec, FuzzFixed32};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let mut u = Unstructured::new(data);

    let a32 = match FuzzFixed32::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };
    let b32 = match FuzzFixed32::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };
    let a_vec = match FuzzDynamicVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };
    let b_vec = match FuzzDynamicVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    // === Fixed<[u8; 32]> — ct_eq ===

    assert!(a32.ct_eq(&a32), "Fixed ct_eq reflexivity failed");
    assert!(b32.ct_eq(&b32), "Fixed ct_eq reflexivity failed (b)");

    assert_eq!(
        a32.ct_eq(&b32),
        b32.ct_eq(&a32),
        "Fixed ct_eq symmetry violated"
    );

    let a_inner = a32.expose_secret();
    let b_inner = b32.expose_secret();
    if a_inner != b_inner {
        assert!(!a32.ct_eq(&b32), "Fixed ct_eq incorrectly returned true for different values");
    } else {
        assert!(a32.ct_eq(&b32), "Fixed ct_eq incorrectly returned false for equal values");
    }

    // === Dynamic<Vec<u8>> — ct_eq ===

    assert!(a_vec.ct_eq(&a_vec), "Dynamic<Vec> ct_eq reflexivity failed");

    assert_eq!(
        a_vec.ct_eq(&b_vec),
        b_vec.ct_eq(&a_vec),
        "Dynamic<Vec> ct_eq symmetry violated"
    );

    if a_vec.expose_secret().len() != b_vec.expose_secret().len() {
        assert!(
            !a_vec.ct_eq(&b_vec),
            "ct_eq returned true for different-length Vecs"
        );
    }

    let av = a_vec.expose_secret();
    let bv = b_vec.expose_secret();
    if av != bv {
        assert!(!a_vec.ct_eq(&b_vec), "Dynamic ct_eq incorrectly true for different values");
    } else {
        assert!(a_vec.ct_eq(&b_vec), "Dynamic ct_eq incorrectly false for equal values");
    }

    // === Edge cases ===

    let empty_a = Dynamic::<Vec<u8>>::new(vec![]);
    let empty_b = Dynamic::<Vec<u8>>::new(vec![]);
    assert!(empty_a.ct_eq(&empty_b), "empty ct_eq should be true");

    let one_a = Dynamic::<Vec<u8>>::new(vec![data[0]]);
    let one_b = Dynamic::<Vec<u8>>::new(vec![data[0]]);
    let one_c = Dynamic::<Vec<u8>>::new(vec![!data[0]]);
    assert!(one_a.ct_eq(&one_b), "single-byte ct_eq same should be true");
    if data[0] != !data[0] {
        assert!(!one_a.ct_eq(&one_c), "single-byte ct_eq diff should be false");
    }

    let zeros = Dynamic::<Vec<u8>>::new(vec![0u8; 64]);
    let ones = Dynamic::<Vec<u8>>::new(vec![0xFFu8; 64]);
    assert!(!zeros.ct_eq(&ones), "zeros vs ones ct_eq should be false");
});
