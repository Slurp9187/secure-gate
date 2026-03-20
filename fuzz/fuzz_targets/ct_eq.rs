// fuzz/fuzz_targets/ct_eq.rs
//
// Constant-time equality fuzz target for secure-gate v0.8.0.
//
// Tests ct_eq, ct_eq_hash, and ct_eq_auto for Fixed<[u8;32]> and Dynamic<Vec<u8>>.
// Verifies reflexivity, symmetry, and consistency between strategies.
//
// Security invariants checked:
//   - x.ct_eq(&x) == true          (reflexivity)
//   - x.ct_eq(&y) == y.ct_eq(&x)   (symmetry)
//   - ct_eq(&a, &b) == false when a != b (correctness)
//   - ct_eq_auto and ct_eq_hash agree for equal inputs
//   - Empty/single-byte edge cases don't panic
//
// Corpus seed hints (paste into fuzz/corpus/ct_eq/):
//   \x00\x00\x00\x00 (32 zeros repeated)
//   \xff\xff\xff\xff (32 0xFF repeated)
//   \x00\x01\x02...  (sequential bytes)
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use secure_gate::{ConstantTimeEq, ConstantTimeEqExt, Dynamic, ExposeSecret};
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

    // Reflexivity: a.ct_eq(&a) must always be true
    assert!(a32.ct_eq(&a32), "Fixed ct_eq reflexivity failed");
    assert!(b32.ct_eq(&b32), "Fixed ct_eq reflexivity failed (b)");

    // Symmetry: a.ct_eq(&b) == b.ct_eq(&a)
    assert_eq!(
        a32.ct_eq(&b32),
        b32.ct_eq(&a32),
        "Fixed ct_eq symmetry violated"
    );

    // Correctness: different arrays must not compare equal
    // (unless the fuzzer produced identical random arrays, which is ~2^-256)
    let a_inner = a32.expose_secret();
    let b_inner = b32.expose_secret();
    if a_inner != b_inner {
        assert!(!a32.ct_eq(&b32), "Fixed ct_eq incorrectly returned true for different values");
    } else {
        assert!(a32.ct_eq(&b32), "Fixed ct_eq incorrectly returned false for equal values");
    }

    // === Fixed<[u8; 32]> — ct_eq_hash ===

    // Reflexivity via BLAKE3
    assert!(a32.ct_eq_hash(&a32), "Fixed ct_eq_hash reflexivity failed");

    // Symmetry
    assert_eq!(
        a32.ct_eq_hash(&b32),
        b32.ct_eq_hash(&a32),
        "Fixed ct_eq_hash symmetry violated"
    );

    // ct_eq and ct_eq_hash must agree for equal inputs
    if a32.ct_eq(&b32) {
        assert!(a32.ct_eq_hash(&b32), "ct_eq true but ct_eq_hash false — inconsistent");
    }

    // === Fixed<[u8; 32]> — ct_eq_auto ===

    // Auto with default threshold (32 bytes) → uses ct_eq path for Fixed<[u8;32]>
    let auto_default = a32.ct_eq_auto(&b32);
    let direct = a32.ct_eq(&b32);
    assert_eq!(
        auto_default, direct,
        "ct_eq_auto() disagrees with ct_eq for 32-byte Fixed"
    );

    // Auto with threshold=0 → always uses ct_eq_hash path
    let auto_hash = a32.ct_eq_auto_with_threshold(&b32, 0);
    // ct_eq_hash is probabilistic; for equal inputs it must be true
    if a32.ct_eq(&b32) {
        assert!(auto_hash, "ct_eq_auto_with_threshold(0) false for equal Fixed — hash path broken");
    }

    // Auto with threshold=4096 → always uses ct_eq path (32 <= 4096)
    let auto_ct = a32.ct_eq_auto_with_threshold(&b32, 4096);
    assert_eq!(
        auto_ct, direct,
        "ct_eq_auto_with_threshold(4096) disagrees with ct_eq for 32-byte Fixed"
    );

    // === Dynamic<Vec<u8>> — ct_eq ===

    // Reflexivity
    assert!(a_vec.ct_eq(&a_vec), "Dynamic<Vec> ct_eq reflexivity failed");

    // Symmetry
    assert_eq!(
        a_vec.ct_eq(&b_vec),
        b_vec.ct_eq(&a_vec),
        "Dynamic<Vec> ct_eq symmetry violated"
    );

    // Length mismatch always returns false
    if a_vec.expose_secret().len() != b_vec.expose_secret().len() {
        assert!(
            !a_vec.ct_eq(&b_vec),
            "ct_eq returned true for different-length Vecs"
        );
    }

    // Correctness
    let av = a_vec.expose_secret();
    let bv = b_vec.expose_secret();
    if av != bv {
        assert!(!a_vec.ct_eq(&b_vec), "Dynamic ct_eq incorrectly true for different values");
    } else {
        assert!(a_vec.ct_eq(&b_vec), "Dynamic ct_eq incorrectly false for equal values");
    }

    // === Dynamic<Vec<u8>> — ct_eq_hash ===

    assert!(a_vec.ct_eq_hash(&a_vec), "Dynamic ct_eq_hash reflexivity failed");
    assert_eq!(
        a_vec.ct_eq_hash(&b_vec),
        b_vec.ct_eq_hash(&a_vec),
        "Dynamic ct_eq_hash symmetry violated"
    );

    // ct_eq and ct_eq_hash agree for equal inputs
    if a_vec.ct_eq(&b_vec) {
        assert!(a_vec.ct_eq_hash(&b_vec), "ct_eq true but ct_eq_hash false");
    }

    // === Dynamic<Vec<u8>> — ct_eq_auto ===

    let vec_auto_default = a_vec.ct_eq_auto(&b_vec);
    if a_vec.expose_secret().len() == b_vec.expose_secret().len() {
        let expected = if a_vec.expose_secret().len() <= 32 {
            a_vec.ct_eq(&b_vec)
        } else {
            a_vec.ct_eq_hash(&b_vec)
        };
        assert_eq!(
            vec_auto_default, expected,
            "ct_eq_auto() inconsistent with manual strategy selection"
        );
    } else {
        assert!(!vec_auto_default, "ct_eq_auto must be false for different-length Vecs");
    }

    // === Edge cases ===

    // Empty Vecs are equal to each other
    let empty_a = Dynamic::<Vec<u8>>::new(vec![]);
    let empty_b = Dynamic::<Vec<u8>>::new(vec![]);
    assert!(empty_a.ct_eq(&empty_b), "empty ct_eq should be true");
    assert!(empty_a.ct_eq_hash(&empty_b), "empty ct_eq_hash should be true");
    assert!(empty_a.ct_eq_auto(&empty_b), "empty ct_eq_auto should be true");

    // Single byte: equal vs. different
    let one_a = Dynamic::<Vec<u8>>::new(vec![data[0]]);
    let one_b = Dynamic::<Vec<u8>>::new(vec![data[0]]);
    let one_c = Dynamic::<Vec<u8>>::new(vec![!data[0]]);
    assert!(one_a.ct_eq(&one_b), "single-byte ct_eq same should be true");
    if data[0] != !data[0] {
        assert!(!one_a.ct_eq(&one_c), "single-byte ct_eq diff should be false");
    }

    // All-zeros vs all-ones (large)
    let zeros = Dynamic::<Vec<u8>>::new(vec![0u8; 64]);
    let ones = Dynamic::<Vec<u8>>::new(vec![0xFFu8; 64]);
    assert!(!zeros.ct_eq(&ones), "zeros vs ones ct_eq should be false");
    assert!(!zeros.ct_eq_hash(&ones), "zeros vs ones ct_eq_hash should be false");
});
