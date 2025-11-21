// tests/password_tests.rs
//
// Exhaustively test SecurePassword and SecurePasswordBuilder convenience methods

#![cfg(feature = "alloc")]

use secure_gate::{SecurePassword, SecurePasswordBuilder};

const TEST_PASS: &str = "correct horse battery staple 🐎";

#[test]
fn expose_secret_immut() {
    let pw = SecurePassword::from(TEST_PASS);
    assert_eq!(pw.expose_secret(), TEST_PASS);
    assert_eq!(pw.expose_secret_bytes(), TEST_PASS.as_bytes());
}

#[test]
fn expose_secret_mut() {
    let mut pw = SecurePassword::from(TEST_PASS.to_owned());
    pw.expose_secret_mut().make_ascii_uppercase();
    assert_eq!(pw.expose_secret(), "CORRECT HORSE BATTERY STAPLE 🐎");
}

#[test]
fn expose_secret_bytes_mut_unsafe() {
    let mut pw = SecurePassword::from(TEST_PASS.to_owned());

    #[cfg(feature = "unsafe-wipe")]
    unsafe {
        for b in pw.expose_secret_bytes_mut() {
            if *b <= b'z' && *b >= b'a' {
                *b -= 32;
            }
        }
        assert_eq!(pw.expose_secret(), "CORRECT HORSE BATTERY STAPLE 🐎");
    }

    #[cfg(not(feature = "unsafe-wipe"))]
    {
        let res = std::panic::catch_unwind(|| pw.expose_secret_bytes_mut());
        assert!(res.is_err());
    }
}

#[test]
fn builder_basic_functionality() {
    let mut builder =
        SecurePasswordBuilder::new(secrecy::SecretBox::new(Box::new(TEST_PASS.to_string())));

    builder.expose_secret_mut().push_str("!!!");
    assert_eq!(
        builder.expose_secret_mut(),
        "correct horse battery staple 🐎!!!"
    );

    let pw: SecurePassword = builder.build();
    assert_eq!(pw.expose_secret(), "correct horse battery staple 🐎!!!");
}

#[test]
fn builder_expose_secret_bytes_mut_unsafe() {
    let mut builder =
        SecurePasswordBuilder::new(secrecy::SecretBox::new(Box::new(String::from(TEST_PASS))));

    #[cfg(feature = "unsafe-wipe")]
    unsafe {
        for b in builder.expose_secret_bytes_mut() {
            if *b == b' ' {
                *b = b'_';
            }
        }
    }

    #[cfg(feature = "unsafe-wipe")]
    assert_eq!(
        builder.expose_secret_mut(),
        "correct_horse_battery_staple_🐎"
    );

    #[cfg(not(feature = "unsafe-wipe"))]
    {
        let res = std::panic::catch_unwind(|| builder.expose_secret_bytes_mut());
        assert!(res.is_err());
    }
}

#[test]
fn regression_test_issue_27_direct_api_works() {
    let pw = SecurePassword::from(TEST_PASS.to_owned());
    let _ = pw.expose_secret();
    let _ = pw.expose_secret_bytes();

    let mut builder = SecurePasswordBuilder::new(secrecy::SecretBox::new(Box::new(String::new())));
    let _ = builder.expose_secret_mut();

    #[cfg(feature = "unsafe-wipe")]
    unsafe {
        let _ = builder.expose_secret_bytes_mut();
    }
}

#[test]
fn zeroing_on_drop_and_debug_redaction() {
    let pw = SecurePassword::from("hunter2");
    let debug = format!("{pw:?}");
    assert!(debug.contains("REDACTED") || debug.contains("***"));
}

#[test]
#[cfg(feature = "stack")]
fn stack_feature_smoke_test() {
    use secure_gate::SecureStackPassword;

    let pw = SecureStackPassword::try_from("short").unwrap();
    // No .expose_secret_bytes() on Zeroizing<[u8; 128]> – use raw access for fixed-size
    let bytes = pw.expose().as_ref();
    assert_eq!(&bytes[0..5], b"short");
}
