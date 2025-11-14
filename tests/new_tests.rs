use secure_gate::{secure, Secure, SecureBytes, SecureStr};
// NEW: Test macro array overload (e.g., for keys/nonces)
#[test]
fn test_macro_array() {
    let key: Secure<[u8; 4]> = secure!([u8; 4], [1, 2, 3, 4]);
    assert_eq!(key.expose(), &[1, 2, 3, 4]);
}
// NEW: Test SecureBytes (unsized slice)
#[test]
fn test_secure_bytes() {
    let bytes: SecureBytes = vec![0xAA, 0xBB].into();
    assert_eq!(bytes.expose(), b"\xAA\xBB");
    let cloned = bytes.clone();
    assert_eq!(cloned.expose(), b"\xAA\xBB");
}
// NEW: Test SecureStr (unsized str)
#[test]
fn test_secure_str() {
    let s: SecureStr = "hello".parse().unwrap();
    assert_eq!(s.expose(), "hello");
    let from_str: SecureStr = "world".into();
    assert_eq!(from_str.expose(), "world");
}
// NEW: Test fixed-size alias (e.g., SecureKey32)
#[test]
fn test_secure_key() {
    let key: secure_gate::SecureKey32 = [0u8; 32].into();
    assert_eq!(key.expose(), &[0u8; 32]);
}
// NEW: Serde round-trip (requires "serde" feature)
#[cfg(feature = "serde")]
#[test]
fn test_serde_roundtrip() {
    use secure_gate::SecurePassword;
    let original = "secret123";
    // FIXED: Use .into() for Secure<SecretString>
    let pw: SecurePassword = original.into();
    let json = serde_json::to_string(&pw.expose()).unwrap();
    assert_eq!(json, r#""secret123""#);
    let round: SecurePassword = serde_json::from_str(&json).unwrap();
    // FIXED: Use .as_str() for comparison
    assert_eq!(round.expose().as_str(), original);
}
// NEW: Basic zeroize verification (requires "zeroize"; manual impl for observable zeroization)
#[cfg(feature = "zeroize")]
#[test]
fn test_zeroize_on_drop() {
    use zeroize::{DefaultIsZeroes, Zeroize};
    #[derive(Clone, Copy, Debug, Default)]
    struct CheckMe(u32);
    impl DefaultIsZeroes for CheckMe {}
    impl CheckMe {
        fn is_zeroed(&self) -> bool {
            self.0 == 0
        }
    }
    // Test manual zeroize (via blanket impl: sets to Default::default())
    let mut sec: Secure<CheckMe> = Secure::new(CheckMe(42));
    assert!(!sec.expose().is_zeroed());
    sec.zeroize();
    assert!(sec.expose().is_zeroed());
    // For OnDrop: Drop triggers auto-zeroize; can't inspect post-drop without unsafe,
    // but we trust secrecy's impl. This confirms the chain works.
    let _sec_dropped: Secure<CheckMe> = Secure::new(CheckMe(42));
    // Placeholder: In CI, could use valgrind/ASan for wipe verification.
}
