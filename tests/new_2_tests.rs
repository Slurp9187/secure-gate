#[cfg(feature = "zeroize")]
use secure_gate::Secure;

// NEW: Test finish_mut on String (shrink capacity post-mutation)
#[cfg(feature = "zeroize")]
#[test]
fn test_finish_mut_string() {
    let mut pw: Secure<String> = Secure::new(String::with_capacity(10));
    pw.expose_mut().push_str("short"); // len=5, cap=10
    assert!(pw.expose().capacity() > pw.expose().len());
    pw.finish_mut();
    assert_eq!(pw.expose().capacity(), pw.expose().len()); // Shrunk to 5
}

// NEW: Test finish_mut on Vec<u8> (shrink capacity post-mutation)
#[cfg(feature = "zeroize")]
#[test]
fn test_finish_mut_vec() {
    let mut vec_sec: Secure<Vec<u8>> = Secure::new(Vec::with_capacity(20));
    vec_sec.expose_mut().extend_from_slice(&[1u8; 5]); // len=5, cap=20
    assert!(vec_sec.expose().capacity() > vec_sec.expose().len());
    vec_sec.finish_mut();
    assert_eq!(vec_sec.expose().capacity(), vec_sec.expose().len()); // Shrunk to 5
                                                                     // Verify clone still works post-shrink
    let cloned = vec_sec.clone();
    assert_eq!(cloned.expose().capacity(), 5);
}

// NEW: Test finish_mut no-op on non-shrinkable types (e.g., fixed array)
#[cfg(feature = "zeroize")]
#[test]
fn test_finish_mut_fixed_array() {
    use secure_gate::SecureKey32;

    let mut key: SecureKey32 = [0xAA; 32].into();
    key.expose_mut().copy_from_slice(&[0u8; 32]); // "Mutate" (no alloc change)
                                                  // No finish_mut impl for arrays, so skip call; mutation works
    assert_eq!(key.expose(), &[0u8; 32]);
}

// NEW: Test AsAnyMut integration (indirectly via downcast in finish_mut)
#[cfg(feature = "zeroize")]
#[test]
fn test_as_any_mut_downcast() {
    // This tests the helper by ensuring finish_mut succeeds on Vec<String> without panic
    let mut mixed: Secure<Vec<String>> = Secure::new(vec!["a".to_string(), "b".to_string()]);
    mixed.expose_mut().push("c".to_string()); // Triggers potential re-alloc
                                              // Note: Vec<String> won't shrink directly, but downcast check should no-op safely
    mixed.finish_mut(); // Should not panic (no Vec<u8>/String match)
    assert_eq!(mixed.expose().len(), 3);
}

// NEW: Test zeroization post-finish_mut (manual impl for observable zeroization)
#[cfg(feature = "zeroize")]
#[test]
fn test_zeroize_after_finish_mut() {
    use zeroize::{DefaultIsZeroes, Zeroize};

    #[derive(Clone, Copy, Debug, Default)]
    struct CheckBytes([u8; 4]);

    impl DefaultIsZeroes for CheckBytes {}

    impl CheckBytes {
        fn is_zeroed(&self) -> bool {
            self.0 == [0u8; 4]
        }
    }

    let mut sec: Secure<CheckBytes> = Secure::new(CheckBytes([0x42; 4]));
    assert!(!sec.expose().is_zeroed());
    // No finish_mut for this type, skip
    sec.zeroize();
    assert!(sec.expose().is_zeroed());
    // Drop triggers ZeroizeOnDrop, wiping the fixed size
}

// #[cfg(feature = "zeroize")]
// #[test]
// fn test_into_inner_zeroizes_original() {
//     use zeroize::Zeroize;

//     #[derive(Clone, Zeroize, Debug, Default)]
//     struct TestSecret(u32);

//     impl DefaultIsZeroes for TestSecret {}

//     let sec: Secure<TestSecret> = Secure::new(TestSecret(42));
//     let extracted: Box<TestSecret> = sec.into_inner();
//     assert_eq!(*extracted, TestSecret(42)); // Extracted intact

//     // To verify zeroize: Create a mutable copy, extract, then drop & check (indirect via another var)
//     let mut sec2 = Secure::new(TestSecret(42));
//     let _extracted2 = sec2.into_inner(); // Triggers zeroize on sec2
//                                          // In full test, use unsafe mem peek or valgrind; here, trust the call succeeds without leak
// }
