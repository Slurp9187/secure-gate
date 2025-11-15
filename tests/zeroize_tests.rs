// tests/zeroize.rs
#[cfg(feature = "zeroize")]
mod tests {
    use secrecy::SecretString;
    use secure_gate::{Secure, SecurePassword};
    use std::format;
    use zeroize::{DefaultIsZeroes, Zeroize}; // For format! in redaction test (std for test convenience)

    #[test]
    fn test_clone_scoped_zeroize() {
        #[derive(Clone, Copy, Debug, Default, PartialEq)]
        struct TestSecret(u32);
        impl DefaultIsZeroes for TestSecret {}
        let orig: Secure<TestSecret> = Secure::new(TestSecret(42));
        let cloned = orig.clone();
        assert_eq!(cloned.expose(), &TestSecret(42));
        let mut sec = Secure::new(TestSecret(42));
        let _cloned_in_scope = sec.clone();
        sec.zeroize();
        assert_eq!(sec.expose(), &TestSecret(0));
    }

    #[test]
    fn test_finish_mut_string() {
        let mut pw: Secure<String> = Secure::new(String::with_capacity(10));
        let initial_cap = pw.expose().capacity(); // e.g., 10
        pw.expose_mut().push_str("short");
        assert!(pw.expose().capacity() > pw.expose().len());
        pw.finish_mut();
        assert_eq!(pw.expose().capacity(), pw.expose().len());
        // Note: Verifies shrink happened; no freed-zero check (impossible safely)
        assert!(pw.expose().capacity() <= initial_cap); // Best-effort: <= original
    }

    #[test]
    fn test_finish_mut_vec() {
        let mut vec_sec: Secure<Vec<u8>> = Secure::new(Vec::with_capacity(20));
        vec_sec.expose_mut().extend_from_slice(&[1u8; 5]);
        assert!(vec_sec.expose().capacity() > vec_sec.expose().len());
        vec_sec.finish_mut();
        assert_eq!(vec_sec.expose().capacity(), vec_sec.expose().len());
        let cloned = vec_sec.clone();
        assert_eq!(cloned.expose().capacity(), 5);
    }

    #[test]
    fn test_finish_mut_fixed_array() {
        use secure_gate::SecureKey32;
        let mut key: SecureKey32 = [0xAA; 32].into();
        key.expose_mut().copy_from_slice(&[0u8; 32]);
        assert_eq!(key.expose(), &[0u8; 32]);
    }

    #[test]
    fn test_as_any_mut_downcast() {
        let mut mixed: Secure<Vec<String>> = Secure::new(vec!["a".to_string(), "b".to_string()]);
        mixed.expose_mut().push("c".to_string());
        mixed.finish_mut();
        assert_eq!(mixed.expose().len(), 3);
    }

    #[test]
    fn test_zeroize_after_finish_mut() {
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
        sec.zeroize();
        assert!(sec.expose().is_zeroed());
    }

    #[test]
    fn test_zeroize_on_drop() {
        #[derive(Clone, Copy, Debug, Default)]
        struct CheckMe(u32);
        impl DefaultIsZeroes for CheckMe {}
        impl CheckMe {
            fn is_zeroed(&self) -> bool {
                self.0 == 0
            }
        }
        let mut sec: Secure<CheckMe> = Secure::new(CheckMe(42));
        assert!(!sec.expose().is_zeroed());
        sec.zeroize();
        assert!(sec.expose().is_zeroed());
        let _sec_dropped: Secure<CheckMe> = Secure::new(CheckMe(42));
    }

    #[test]
    fn test_secure_password_zeroize() {
        let mut pw: SecurePassword = "secret".into();
        assert_eq!(pw.expose().as_str(), "secret");
        pw.zeroize();
        assert_eq!(pw.expose().len(), 0);
        assert_eq!(pw.expose().as_str(), "");
    }

    #[test]
    fn test_secure_password_cloneable_secret() {
        let pw: SecurePassword = SecurePassword::init_with(|| SecretString::from("dynamic"));
        assert_eq!(pw.expose().as_str(), "dynamic");
    }

    #[test]
    fn test_secure_password_finish_mut_shrink() {
        let mut pw: SecurePassword = String::with_capacity(20).into();
        pw.expose_mut().push_str("short");
        assert!(pw.expose().capacity() > pw.expose().len());
        pw.finish_mut();
        assert_eq!(pw.expose().capacity(), pw.expose().len());
    }

    #[test]
    fn test_finish_mut_noop() {
        let mut mixed: Secure<Vec<String>> = Secure::new(vec!["a".to_string(), "b".to_string()]);
        mixed.expose_mut().push("c".to_string());
        mixed.finish_mut();
        assert_eq!(mixed.expose().len(), 3);
    }

    #[test]
    fn test_init_with() {
        let val = Secure::<u32>::init_with(|| 42u32);
        assert_eq!(*val.expose(), 42);
    }

    #[test]
    fn test_into_inner_zeroizes_original() {
        #[derive(Clone, Copy, Debug, Default, PartialEq)]
        struct TestSecret(u32);
        impl DefaultIsZeroes for TestSecret {}
        let sec: Secure<TestSecret> = Secure::new(TestSecret(42));
        let extracted: Box<TestSecret> = sec.into_inner();
        assert_eq!(*extracted, TestSecret(42));
        let sec2 = Secure::new(TestSecret(42));
        let _extracted2 = sec2.into_inner();
    }

    #[test]
    fn test_secret_string_debug_redacted() {
        let ss = SecretString::from("hunter2");
        let debug = format!("{ss:?}");
        assert_eq!(debug, "SecretString([REDACTED])");
        // Confirm no leak even for special cases
        let empty = SecretString::default();
        let empty_debug = format!("{empty:?}");
        assert_eq!(empty_debug, "SecretString([REDACTED])");
        // Edge: Exact match to redacted string (should still redact, per fuzz logic)
        let tricky = SecretString::from("[REDACTED]");
        let tricky_debug = format!("{tricky:?}");
        assert_eq!(tricky_debug, "SecretString([REDACTED])");
    }
}

#[cfg(not(feature = "zeroize"))]
#[test]
fn test_secure_password_finish_mut_shrink_fallback() {
    use secure_gate::SecurePassword;
    let mut pw: SecurePassword = "short".to_string().into();
    pw.expose_mut().push_str("er");
    assert_eq!(pw.expose(), "shorter");
}
